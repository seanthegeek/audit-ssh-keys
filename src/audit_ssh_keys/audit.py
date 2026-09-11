"""Audit every SSH key on a local Linux server.

Three sections:

  host keys        The server's own identity keys (HostKey directives, or the
                   OpenSSH defaults): algorithm/size, ownership/permissions,
                   and whether sshd's accepted-algorithm lists still allow
                   weak signature schemes.

  authorized_keys  Every authorized_keys file for every local account, using
                   the effective sshd AuthorizedKeysFile pattern: key strength,
                   what StrictModes would reject, keys reused across accounts,
                   unrestricted keys on uid-0 accounts.

  private keys     Private keys sitting in each account's ~/.ssh: algorithm/
                   size, ownership/permissions, and whether they are
                   passphrase-protected.

Also reports when sshd sources keys from somewhere a file audit cannot see
(AuthorizedKeysCommand, TrustedUserCAKeys).

Usage:
    sudo audit-ssh-keys [--json] [--min-rsa-bits 3072]
                        [--skip-host] [--skip-authorized] [--skip-private]

Run as root: other users' files are unreadable otherwise, and `sshd -T`
(used to read the effective config) needs root.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import logging
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

try:
    from audit_ssh_keys import __version__
except ImportError:
    # audit.py can be copied to a host on its own (see docs/usage.md, "Fleet
    # use") and run without the rest of the package, so this lookup must not
    # be a hard dependency.
    __version__ = "unknown"

logger = logging.getLogger(__name__)


class AuditError(RuntimeError):
    """Raised when the audit cannot run at all (for example, ssh-keygen is missing)."""


DEFAULT_MIN_RSA_BITS = 3072
DEFAULT_AUTHORIZED_KEYS_PATTERNS = [".ssh/authorized_keys", ".ssh/authorized_keys2"]
DEFAULT_HOST_KEYS = [
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssh/ssh_host_dsa_key",  # not a modern default, but audit it if present
]
SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SSHD_CONFIG_D = Path("/etc/ssh/sshd_config.d")

# Key-type tokens that can start a bare (option-less) authorized_keys entry.
KEY_TYPE_PREFIXES = (
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-",
    "sk-ecdsa-sha2-",
    "sk-ssh-ed25519",
    "ssh-xmss",
)

# Signature algorithm names in sshd's *Algorithms lists that should not be accepted.
WEAK_SIG_ALGORITHMS = {
    "ssh-dss": "DSA signatures",
    "ssh-dss-cert-v01@openssh.com": "DSA certificate signatures",
    "ssh-rsa": "RSA with SHA-1 signatures",
    "ssh-rsa-cert-v01@openssh.com": "RSA certificate with SHA-1 signatures",
}

PRIVATE_KEY_HEADERS = (
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class Issue:
    """A single finding with a severity: CRITICAL, HIGH, MEDIUM, LOW, INFO."""

    severity: str
    message: str


@dataclass
class HostKeyFinding:
    """One sshd host key."""

    path: str
    key_type: str
    bits: int
    fingerprint: str
    issues: list[Issue] = field(default_factory=list)


@dataclass
class AuthorizedKeyFinding:
    """A parsed authorized_keys entry."""

    user: str
    file_path: str
    line_number: int
    key_type: str
    bits: int
    fingerprint: str
    comment: str
    options: list[str]
    issues: list[Issue] = field(default_factory=list)


@dataclass
class FileFinding:
    """File-level (not per-key) issues for one authorized_keys file."""

    user: str
    file_path: str
    key_count: int
    issues: list[Issue] = field(default_factory=list)


@dataclass
class PrivateKeyFinding:
    """A private key found in a user's ~/.ssh.

    encrypted is True (passphrase-protected), False (no passphrase), or None
    when the file format could not be recognised and neither could be determined.
    """

    user: str
    path: str
    key_type: str
    bits: int
    fingerprint: str
    encrypted: bool | None
    issues: list[Issue] = field(default_factory=list)


@dataclass
class Report:
    """Full audit output."""

    config_source: str
    effective_authorized_keys_file: list[str]
    coverage_warnings: list[str]
    server_config_issues: list[Issue]
    host_keys: list[HostKeyFinding]
    authorized_key_files: list[FileFinding]
    authorized_keys: list[AuthorizedKeyFinding]
    duplicate_authorized_keys: dict[str, list[str]]
    private_keys: list[PrivateKeyFinding]


# --------------------------------------------------------------------------- #
# sshd configuration
# --------------------------------------------------------------------------- #


def read_effective_sshd_config(
    sshd_bin: str | None = None,
    config_paths: list[Path] | None = None,
) -> tuple[dict[str, list[str]], str, str]:
    """Return (config, source, sshd_error) for the effective sshd config.

    config maps each lowercased keyword to a list of values (a list because
    some keywords, like HostKey, legitimately repeat). Prefers `sshd -T`,
    which resolves Include directives and gives the effective (non-Match)
    values. Falls back to a naive parse of sshd_config + sshd_config.d/*.conf
    when sshd isn't installed or -T fails.
    """
    config: dict[str, list[str]] = defaultdict(list)
    sshd_error = ""

    sshd = sshd_bin if sshd_bin is not None else _find_sshd()
    if sshd:
        try:
            proc = subprocess.run([sshd, "-T"], capture_output=True, text=True, check=False)
        except OSError as exc:
            proc = None
            sshd_error = str(exc)
        if proc is not None and proc.returncode == 0 and proc.stdout.strip():
            return _parse_sshd_t_output(proc.stdout), "sshd -T", ""
        if proc is not None:
            logger.debug("sshd -T exited %s: %s", proc.returncode, proc.stderr.strip())
            # sshd -T validates the whole config, so its stderr is itself a finding.
            lines = [ln for ln in proc.stderr.replace("\r", "").splitlines() if ln.strip() and not ln.startswith("@")]
            sshd_error = "; ".join(lines[:6])
    else:
        sshd_error = "sshd binary not found"

    # Fallback: naive parse. Ignores Match blocks. First occurrence wins for
    # single-valued keywords; HostKey accumulates.
    if config_paths is None:
        config_paths = [SSHD_CONFIG]
        if SSHD_CONFIG_D.is_dir():
            config_paths.extend(sorted(SSHD_CONFIG_D.glob("*.conf")))
    for cfg in config_paths:
        if not cfg.is_file():
            continue
        try:
            text = cfg.read_text(errors="ignore")
        except OSError:
            continue
        in_match = False
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"\s+|=", line, maxsplit=1)
            if len(parts) != 2:
                continue
            key, value = parts[0].lower(), parts[1].strip()
            if key == "match":
                in_match = True
                continue
            if in_match:
                continue
            if key == "hostkey" or key not in config:
                config[key].append(value)
    return dict(config), "parsed sshd_config (sshd -T unavailable)", sshd_error


def _parse_sshd_t_output(stdout: str) -> dict[str, list[str]]:
    """Turn the output of `sshd -T` into {lowercased keyword: [values]}.

    Each line is "keyword value". Values are collected in a list because a few
    keywords (HostKey, for one) can appear more than once.
    """
    config: dict[str, list[str]] = defaultdict(list)
    for line in stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            config[parts[0].lower()].append(parts[1].strip())
    return dict(config)


def read_user_sshd_config(user_name: str, sshd_bin: str) -> dict[str, list[str]] | None:
    """Return the effective sshd config for one account, or None if it cannot be read.

    Plain `sshd -T` prints the configuration with no `Match` block applied.
    Adding `-C user=<name>` tells sshd to work out the configuration it would
    use for that account, so `Match User` and `Match Group` blocks that change
    AuthorizedKeysFile are honoured. Criteria that depend on an actual
    connection (`Match Address`, `LocalPort`, and friends) cannot be evaluated
    here, so sshd treats them as not matching.

    Returns None when sshd cannot be run, exits non-zero, or prints nothing;
    the caller then falls back to the global configuration.
    """
    try:
        proc = subprocess.run(
            [sshd_bin, "-T", "-C", f"user={user_name}"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        logger.debug("could not run sshd -T -C user=%s: %s", user_name, exc)
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        logger.debug("sshd -T -C user=%s exited %s: %s", user_name, proc.returncode, proc.stderr.strip())
        return None
    return _parse_sshd_t_output(proc.stdout)


def _find_sshd() -> str | None:
    """Locate the sshd binary; it usually lives in a sbin dir that is not on a user's PATH."""
    found = shutil.which("sshd")
    if found:
        return found
    for candidate in ("/usr/sbin/sshd", "/usr/local/sbin/sshd"):
        if Path(candidate).exists():
            return candidate
    return None


def cfg_value(config: dict[str, list[str]], key: str, default: str) -> str:
    """First value for a single-valued keyword, or default."""
    values = config.get(key)
    return values[0] if values else default


def expand_authorized_keys_pattern(pattern: str, user: pwd.struct_passwd) -> str:
    """Expand sshd AuthorizedKeysFile tokens (%%, %h, %u, %U) for one account."""
    path = (
        pattern.replace("%%", "\x00")
        .replace("%h", user.pw_dir)
        .replace("%u", user.pw_name)
        .replace("%U", str(user.pw_uid))
        .replace("\x00", "%")
    )
    if not path.startswith("/"):
        path = str(Path(user.pw_dir) / path)
    return path


# --------------------------------------------------------------------------- #
# ssh-keygen helpers
# --------------------------------------------------------------------------- #


def pub_sibling(path: Path) -> Path:
    """The public-key file that would sit next to a private key: the full name plus '.pub'.

    Not `path.with_suffix(".pub")` — that replaces text after the last dot in
    the name, which mangles a private key file whose name already contains a
    dot (for example, ``host.key`` becomes ``host.pub`` instead of
    ``host.key.pub``).
    """
    return path.with_name(path.name + ".pub")


def parse_fingerprint_output(out: str) -> tuple[str, int, str, str] | None:
    """Parse `ssh-keygen -l` output into (type, bits, fingerprint, comment)."""
    # "2048 SHA256:... comment (RSA)"; comment may itself contain parentheses.
    m = re.match(r"^(\d+)\s+(\S+)\s+(.*?)\s+\((\S+)\)\s*$", out.strip())
    if not m:
        return None
    bits, fingerprint, comment, key_type = m.groups()
    if comment == "no comment":
        comment = ""
    return key_type, int(bits), fingerprint, comment


def fingerprint_line(key_line: str) -> tuple[str, int, str, str] | None:
    """Fingerprint one public-key line via `ssh-keygen -lf -`."""
    proc = subprocess.run(
        ["ssh-keygen", "-lf", "-"],
        input=key_line + "\n",
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return parse_fingerprint_output(proc.stdout)


def fingerprint_file(path: Path) -> tuple[str, int, str, str] | None:
    """Fingerprint a key file (public or unencrypted private) via `ssh-keygen -lf`."""
    proc = subprocess.run(
        ["ssh-keygen", "-lf", str(path)],
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        return None
    return parse_fingerprint_output(proc.stdout)


def _read_uint32(buf: bytes, offset: int) -> tuple[int, int]:
    """Read a big-endian 32-bit number at offset; return (value, offset after it).

    Raises ValueError if the four bytes are not all present.
    """
    if offset < 0 or offset + 4 > len(buf):
        raise ValueError(f"want 4 bytes at offset {offset}, buffer is {len(buf)} bytes")
    return int.from_bytes(buf[offset : offset + 4], "big"), offset + 4


def _read_string(buf: bytes, offset: int) -> tuple[bytes, int]:
    """Read one SSH wire-format string (a 32-bit length then that many bytes).

    Returns (bytes, offset after them). Raises ValueError if the length field
    or the bytes it promises run past the end of buf.
    """
    length, offset = _read_uint32(buf, offset)
    end = offset + length
    if end > len(buf):
        raise ValueError(f"string of {length} bytes at offset {offset} runs past the end of a {len(buf)}-byte buffer")
    return buf[offset:end], end


def _openssh_key_blob(path: Path) -> bytes | None:
    """Decode an OpenSSH-format private key file and return everything after the magic string.

    Returns None when the file cannot be read, is not in OpenSSH's own private
    key format, or its base64 body is corrupt or does not start with the
    expected "openssh-key-v1" marker.
    """
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return None
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines or lines[0] != "-----BEGIN OPENSSH PRIVATE KEY-----":
        return None
    body = "".join(ln for ln in lines[1:] if not ln.startswith("-----"))
    try:
        raw = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return None
    magic = b"openssh-key-v1\x00"
    if not raw.startswith(magic):
        return None
    return raw[len(magic) :]


def public_key_from_private(path: Path) -> str | None:
    """Return the "<type> <base64>" public-key line stored inside an OpenSSH private key file.

    An OpenSSH-format private key file keeps the public half in the clear at
    the front of the file, even when the private half is passphrase-protected.
    That means the key's type, size and fingerprint can be read without the
    passphrase and without ssh-keygen having to open the file (which it refuses
    to do when the file is readable by anyone else).

    Returns None for anything that is not an OpenSSH-format private key, or
    whose contents are truncated or otherwise unreadable.
    """
    blob = _openssh_key_blob(path)
    if blob is None:
        return None
    try:
        _cipher, offset = _read_string(blob, 0)
        _kdf, offset = _read_string(blob, offset)
        _kdf_options, offset = _read_string(blob, offset)
        nkeys, offset = _read_uint32(blob, offset)
        if nkeys < 1:
            return None
        public_blob, _ = _read_string(blob, offset)
        key_type, _ = _read_string(public_blob, 0)
        name = key_type.decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return None
    if not name:
        return None
    return f"{name} {base64.b64encode(public_blob).decode()}"


def fingerprint_private_key(path: Path) -> tuple[tuple[str, int, str, str] | None, Issue | None]:
    """Fingerprint a private key, and check any `.pub` file next to it against it.

    Returns (result, mismatch_issue). result is the (type, bits, fingerprint,
    comment) tuple, or None when the key could not be fingerprinted at all.

    The public half stored inside the private key file is the authoritative
    answer: it is there even when the key is passphrase-protected, and reading
    it does not depend on the file's permissions. A `<name>.pub` file sitting
    next to the key is only compared against it — if the two disagree, the
    `.pub` file is stale or belongs to a different key, and anything copied out
    of it authorises the wrong key.

    Keys in the older PEM formats do not carry a readable public half, so for
    those the `.pub` file is used, and failing that ssh-keygen is asked to read
    the private key directly (which works only when it has no passphrase).
    """
    line = public_key_from_private(path)
    result = fingerprint_line(line) if line else None

    pub = pub_sibling(path)
    pub_result = fingerprint_file(pub) if pub.is_file() else None

    mismatch: Issue | None = None
    if result is not None and pub_result is not None and result[2] != pub_result[2]:
        mismatch = Issue(
            "LOW",
            f"{pub.name} does not match this private key (public file is {pub_result[0]} {pub_result[2]})",
        )

    if result is None:
        result = pub_result
        if result is None and not pub.is_file():
            # ssh-keygen prefers a .pub sibling when one exists, so this is only
            # worth trying when there is none.
            result = fingerprint_file(path)
    return result, mismatch


def private_key_is_encrypted(path: Path) -> bool | None:
    """True if a passphrase is required, False if not, None if the format is unrecognised.

    Decided by inspecting the file rather than invoking ssh-keygen, so it works
    on keys ssh-keygen would refuse to load (for example, world-readable ones):

    * OpenSSH native format: the cipher name embedded after the magic string
      is ``none`` for unencrypted keys.
    * Legacy PEM (RSA/DSA/EC): a ``Proc-Type: 4,ENCRYPTED`` header.
    * PKCS#8: ``BEGIN ENCRYPTED PRIVATE KEY`` vs ``BEGIN PRIVATE KEY``.
    """
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return None
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    header = lines[0]

    if header == "-----BEGIN OPENSSH PRIVATE KEY-----":
        blob = _openssh_key_blob(path)
        if blob is None:
            return None
        try:
            cipher, _ = _read_string(blob, 0)
        except ValueError:
            # Truncated or corrupt body: the cipher name field itself is missing or
            # cut short, so we cannot tell "none" (unencrypted) from an actual cipher.
            return None
        if not cipher:
            return None
        return cipher != b"none"

    if header == "-----BEGIN ENCRYPTED PRIVATE KEY-----":
        return True
    if header == "-----BEGIN PRIVATE KEY-----":
        return False
    if header in (
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
    ):
        return any(ln.startswith("Proc-Type:") and "ENCRYPTED" in ln for ln in lines[1:5])
    return None


def looks_like_private_key(path: Path) -> bool:
    """Cheap header check so we only run ssh-keygen on plausible private keys."""
    try:
        with path.open("rb") as fh:
            head = fh.read(64).decode("ascii", errors="ignore")
    except OSError:
        return False
    return head.lstrip().startswith(PRIVATE_KEY_HEADERS)


# --------------------------------------------------------------------------- #
# authorized_keys line parsing
# --------------------------------------------------------------------------- #


def split_options(line: str) -> tuple[list[str], str]:
    """Split an authorized_keys line into (options, key-material-and-comment).

    Options are comma-separated and may contain quoted strings with commas
    or escaped quotes (e.g. command="foo,bar"). A line that starts directly
    with a key type has no options.
    """
    stripped = line.strip()
    first_token = stripped.split(None, 1)[0]
    if any(first_token.startswith(p) for p in KEY_TYPE_PREFIXES):
        return [], stripped

    options: list[str] = []
    current: list[str] = []
    in_quotes = False
    i = 0
    while i < len(stripped):
        ch = stripped[i]
        if in_quotes:
            if ch == "\\" and i + 1 < len(stripped):
                current.append(stripped[i : i + 2])
                i += 2
                continue
            if ch == '"':
                in_quotes = False
            current.append(ch)
        elif ch == '"':
            in_quotes = True
            current.append(ch)
        elif ch == ",":
            options.append("".join(current))
            current = []
        elif ch in " \t":
            options.append("".join(current))
            return [o for o in options if o], stripped[i:].strip()
        else:
            current.append(ch)
        i += 1
    options.append("".join(current))
    return [o for o in options if o], ""


# --------------------------------------------------------------------------- #
# Grading
# --------------------------------------------------------------------------- #


def grade_key(key_type: str, bits: int, min_rsa_bits: int) -> list[Issue]:
    """Policy issues for a key's algorithm and size."""
    kt = key_type.upper()
    if kt == "RSA1":
        return [Issue("CRITICAL", "SSH-1 RSA key; protocol 1 is obsolete and broken")]
    if kt == "DSA":
        return [Issue("HIGH", "DSA key; deprecated, capped at 1024 bits, disabled by default in modern OpenSSH")]
    if kt == "RSA":
        if bits < 2048:
            return [Issue("CRITICAL", f"RSA {bits}-bit is below 2048 and considered factorable-risk")]
        if bits < min_rsa_bits:
            return [Issue("MEDIUM", f"RSA {bits}-bit is below policy minimum of {min_rsa_bits}")]
    return []


def grade_options(options: list[str], user: pwd.struct_passwd) -> list[Issue]:
    """Issues derived from an authorized_keys entry's options (or lack of them)."""
    names = {o.split("=", 1)[0].lower() for o in options}
    if user.pw_uid == 0 and not ({"from", "command"} & names):
        return [Issue("INFO", "uid-0 account key has no from= or command= restriction")]
    return []


def _check_one_strictmodes_path(p: Path, owner: pwd.struct_passwd) -> list[Issue]:
    """Apply sshd's owner-and-mode rule to a single file or directory.

    The rule: it must be owned by the account or by root, and must not be
    writable by group or others. Read bits are irrelevant. A path that cannot
    be stat'ed is reported LOW, because the tool could not check it.
    """
    try:
        st = p.stat()
    except OSError as exc:
        return [Issue("LOW", f"could not stat {p}: {exc}")]
    issues: list[Issue] = []
    mode = stat.S_IMODE(st.st_mode)
    if st.st_uid not in (owner.pw_uid, 0):
        issues.append(Issue("HIGH", f"{p} is owned by {uid_name(st.st_uid)}, not {_owner_phrase(owner.pw_uid)}"))
    if mode & 0o022:
        issues.append(Issue("HIGH", f"{p} is group/world-writable (mode {mode:04o})"))
    return issues


def check_strictmodes_path(path: Path, owner: pwd.struct_passwd) -> list[Issue]:
    """Replicate what sshd StrictModes enforces for an authorized_keys file.

    sshd follows any symbolic links first, then checks the file itself and
    every directory above it in turn. Each one must be owned by the account or
    by root and must not be writable by group or others. The walk stops once it
    has checked the account's home directory, if the file is inside it; a file
    somewhere else (say under /etc) is checked all the way up to /, which is
    why an authorized_keys file under a world-writable directory such as /tmp
    is rejected outright.

    Anything that would be rejected is HIGH: either the key is silently
    unusable (StrictModes yes) or another account can inject keys
    (StrictModes no).
    """
    try:
        real = path.resolve(strict=True)
    except OSError as exc:
        return [Issue("LOW", f"could not resolve {path}: {exc}")]

    home = Path(owner.pw_dir)
    home_real = home.resolve() if home.exists() else None

    issues = _check_one_strictmodes_path(real, owner)
    for parent in real.parents:
        issues.extend(_check_one_strictmodes_path(parent, owner))
        if home_real is not None and parent == home_real:
            break
    return issues


def check_private_key_perms(path: Path, expected_uid: int) -> list[Issue]:
    """Private keys must be owned by the expected user (or root) and unreadable by group/others.

    sshd applies the same rule to host keys: a host key with any group/other
    permission bits is refused with "UNPROTECTED PRIVATE KEY FILE".
    """
    issues: list[Issue] = []
    try:
        st = path.stat()
    except OSError as exc:
        return [Issue("LOW", f"could not stat {path}: {exc}")]
    mode = stat.S_IMODE(st.st_mode)
    if st.st_uid not in (expected_uid, 0):
        issues.append(Issue("HIGH", f"owned by {uid_name(st.st_uid)}, expected {_owner_phrase(expected_uid)}"))
    if mode & 0o007:
        issues.append(Issue("CRITICAL", f"world-accessible private key (mode {mode:04o})"))
    elif mode & 0o070:
        issues.append(Issue("HIGH", f"group-accessible private key (mode {mode:04o})"))
    return issues


def uid_name(uid: int) -> str:
    """Username for a uid, or the uid as text."""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _owner_phrase(uid: int) -> str:
    """Phrase describing an accepted owner: just 'root' for uid 0, else 'name or root'.

    sshd always accepts root as an alternate owner, so a plain uid-0 case
    should read as "expected root", not the redundant "expected root or root".
    """
    if uid == 0:
        return "root"
    return f"{uid_name(uid)} or root"


# --------------------------------------------------------------------------- #
# Section: server config + host keys
# --------------------------------------------------------------------------- #


def audit_server_config(
    config: dict[str, list[str]], config_source: str, sshd_error: str
) -> tuple[list[Issue], list[str]]:
    """Issues in sshd's algorithm/auth settings, plus coverage warnings for the file audit."""
    issues: list[Issue] = []
    coverage: list[str] = []

    if config_source == "sshd -T":
        # sshd -T prints the effective, fully-expanded algorithm lists.
        for keyword, label in (
            ("hostkeyalgorithms", "HostKeyAlgorithms"),
            ("pubkeyacceptedalgorithms", "PubkeyAcceptedAlgorithms"),
            ("pubkeyacceptedkeytypes", "PubkeyAcceptedKeyTypes"),  # pre-8.5 keyword
            ("casignaturealgorithms", "CASignatureAlgorithms"),
        ):
            for value in config.get(keyword, []):
                accepted = {a.strip() for a in value.split(",")}
                for weak, desc in WEAK_SIG_ALGORITHMS.items():
                    if weak in accepted:
                        issues.append(Issue("MEDIUM", f"{label} accepts {weak} ({desc})"))
    else:
        coverage.append(
            f"sshd -T failed ({sshd_error}); accepted-algorithm lists were not checked "
            "and Match blocks were not applied."
        )

    if cfg_value(config, "authorizedkeyscommand", "none").lower() != "none":
        coverage.append(
            f"AuthorizedKeysCommand is set ({cfg_value(config, 'authorizedkeyscommand', '')}); "
            "keys sourced from it are NOT covered by this file-based audit."
        )
    if cfg_value(config, "trustedusercakeys", "none").lower() != "none":
        coverage.append(
            f"TrustedUserCAKeys is set ({cfg_value(config, 'trustedusercakeys', '')}); "
            "certificate-based logins are NOT covered by this audit."
        )
    if cfg_value(config, "strictmodes", "yes").lower() == "no":
        issues.append(Issue("MEDIUM", "StrictModes is 'no'; sshd will accept insecurely-permissioned key files"))
    if cfg_value(config, "pubkeyauthentication", "yes").lower() == "no":
        coverage.append("PubkeyAuthentication is 'no'; authorized_keys entries are currently inert.")
    if cfg_value(config, "permitrootlogin", "prohibit-password").lower() == "yes":
        issues.append(
            Issue(
                "MEDIUM",
                "PermitRootLogin is 'yes'; permits password login as root when PasswordAuthentication is enabled",
            )
        )
    if cfg_value(config, "passwordauthentication", "yes").lower() == "yes":
        issues.append(Issue("INFO", "PasswordAuthentication is 'yes'; keys are not the only login path"))

    return issues, coverage


def audit_host_keys(config: dict[str, list[str]], min_rsa_bits: int, *, owner_uid: int = 0) -> list[HostKeyFinding]:
    """Fingerprint and grade each configured (or default) host key.

    Host keys must be owned by root, so owner_uid defaults to 0. It is
    injectable (like the repo's other audit functions take users=,
    config_paths=, sshd_bin=) so tests can run as an ordinary user and still
    exercise the ownership check without needing real root-owned files.
    """
    paths = config.get("hostkey") or DEFAULT_HOST_KEYS
    findings: list[HostKeyFinding] = []
    seen: set[str] = set()
    types_present: set[str] = set()

    for p in paths:
        path = Path(p)
        if str(path) in seen:
            continue
        seen.add(str(path))
        if not path.is_file():
            if config.get("hostkey"):
                # Explicitly configured but missing: sshd will log an error for it.
                findings.append(
                    HostKeyFinding(str(path), "?", 0, "", [Issue("LOW", "configured HostKey does not exist")])
                )
            continue

        result, mismatch = fingerprint_private_key(path)
        if result is None:
            findings.append(HostKeyFinding(str(path), "?", 0, "", [Issue("LOW", "could not fingerprint host key")]))
            continue
        key_type, bits, fingerprint, _ = result
        types_present.add(key_type.upper())

        finding = HostKeyFinding(str(path), key_type, bits, fingerprint)
        finding.issues.extend(grade_key(key_type, bits, min_rsa_bits))
        if mismatch is not None:
            finding.issues.append(mismatch)
        perm_issues = check_private_key_perms(path, expected_uid=owner_uid)
        for issue in perm_issues:
            if "accessible" in issue.message:
                issue.message += "; sshd refuses to load it"
        finding.issues.extend(perm_issues)
        enc = private_key_is_encrypted(path)
        if enc is True:
            finding.issues.append(Issue("LOW", "host key is passphrase-protected; sshd cannot load it unattended"))
        findings.append(finding)

    if findings and "ED25519" not in types_present:
        findings.append(
            HostKeyFinding(
                "(none)", "ED25519", 0, "", [Issue("LOW", "no Ed25519 host key present; consider ssh-keygen -A")]
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Section: authorized_keys
# --------------------------------------------------------------------------- #


def audit_authorized_keys(
    config: dict[str, list[str]],
    min_rsa_bits: int,
    users: list[pwd.struct_passwd] | None = None,
    user_config: Callable[[pwd.struct_passwd], dict[str, list[str]] | None] | None = None,
) -> tuple[list[str], list[FileFinding], list[AuthorizedKeyFinding], dict[str, list[str]], list[str]]:
    """Scan every account's authorized_keys files per the effective AuthorizedKeysFile.

    user_config, when given, is asked for each account's own effective config
    (see read_user_sshd_config), so a Match block that changes
    AuthorizedKeysFile for some accounts is honoured. It may return None for an
    account, in which case the global configuration is used for it.

    The returned pattern list is the global one, not any per-account override.
    """
    patterns = cfg_value(config, "authorizedkeysfile", " ".join(DEFAULT_AUTHORIZED_KEYS_PATTERNS)).split()
    coverage: list[str] = []
    if patterns == ["none"]:
        patterns = []
        coverage.append("AuthorizedKeysFile is 'none'; sshd reads no authorized_keys files.")

    files: list[FileFinding] = []
    keys: list[AuthorizedKeyFinding] = []
    fp_locations: dict[str, list[str]] = defaultdict(list)
    # (account, path): sshd consults a shared absolute path for every account,
    # so the same file has to be scanned once per account -- but a pattern
    # listed twice for one account is still only scanned once.
    seen_paths: set[tuple[str, str]] = set()
    # One ssh-keygen call per distinct key line, not per account that has it.
    fingerprints: dict[str, tuple[str, int, str, str] | None] = {}

    for user in sorted(users if users is not None else pwd.getpwall(), key=lambda u: u.pw_uid):
        user_patterns = patterns
        if user_config is not None:
            account_config = user_config(user)
            if account_config is not None:
                user_patterns = cfg_value(
                    account_config, "authorizedkeysfile", " ".join(DEFAULT_AUTHORIZED_KEYS_PATTERNS)
                ).split()
        if user_patterns == ["none"]:
            coverage.append(
                f"AuthorizedKeysFile is 'none' for {user.pw_name} (Match block); "
                "sshd reads no authorized_keys files for that account."
            )
            continue

        for pattern in user_patterns:
            path = Path(expand_authorized_keys_pattern(pattern, user))
            if (user.pw_name, str(path)) in seen_paths or not path.is_file():
                continue
            seen_paths.add((user.pw_name, str(path)))

            file_finding = FileFinding(user=user.pw_name, file_path=str(path), key_count=0)
            file_finding.issues.extend(check_strictmodes_path(path, user))

            try:
                lines = path.read_text(errors="ignore").splitlines()
            except OSError as exc:
                file_finding.issues.append(Issue("LOW", f"could not read file: {exc}"))
                files.append(file_finding)
                continue

            for idx, raw in enumerate(lines, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                options, key_material = split_options(line)
                if not key_material:
                    result = None
                elif key_material in fingerprints:
                    result = fingerprints[key_material]
                else:
                    result = fingerprint_line(key_material)
                    fingerprints[key_material] = result
                if result is None:
                    file_finding.issues.append(Issue("LOW", f"line {idx}: unparseable entry (ignored by sshd)"))
                    continue
                key_type, bits, fingerprint, comment = result
                file_finding.key_count += 1

                finding = AuthorizedKeyFinding(
                    user=user.pw_name,
                    file_path=str(path),
                    line_number=idx,
                    key_type=key_type,
                    bits=bits,
                    fingerprint=fingerprint,
                    comment=comment,
                    options=options,
                )
                finding.issues.extend(grade_key(key_type, bits, min_rsa_bits))
                finding.issues.extend(grade_options(options, user))
                keys.append(finding)
                fp_locations[fingerprint].append(f"{user.pw_name} {path}:{idx}")

            files.append(file_finding)

    duplicates = {fp: locs for fp, locs in fp_locations.items() if len(locs) > 1}
    for finding in keys:
        if finding.fingerprint in duplicates:
            here = f"{finding.user} {finding.file_path}:{finding.line_number}"
            others = [loc for loc in duplicates[finding.fingerprint] if loc != here]
            finding.issues.append(Issue("MEDIUM", f"same key also authorized at: {', '.join(others)}"))

    return patterns, files, keys, duplicates, coverage


# --------------------------------------------------------------------------- #
# Section: user private keys
# --------------------------------------------------------------------------- #


def audit_private_keys(
    min_rsa_bits: int,
    host_key_paths: set[str],
    users: list[pwd.struct_passwd] | None = None,
) -> list[PrivateKeyFinding]:
    """Find private keys in every account's ~/.ssh and grade them."""
    findings: list[PrivateKeyFinding] = []
    seen: set[str] = set()

    for user in sorted(users if users is not None else pwd.getpwall(), key=lambda u: u.pw_uid):
        ssh_dir = Path(user.pw_dir) / ".ssh"
        if not ssh_dir.is_dir() or str(ssh_dir) in seen:
            continue
        seen.add(str(ssh_dir))
        try:
            entries = sorted(p for p in ssh_dir.iterdir() if p.is_file() and not p.is_symlink())
        except OSError:
            continue

        for path in entries:
            if str(path) in host_key_paths or path.suffix == ".pub" or not looks_like_private_key(path):
                continue

            encrypted = private_key_is_encrypted(path)
            finding = PrivateKeyFinding(
                user=user.pw_name,
                path=str(path),
                key_type="?",
                bits=0,
                fingerprint="",
                encrypted=encrypted,
            )
            result, mismatch = fingerprint_private_key(path)
            if result is not None:
                finding.key_type, finding.bits, finding.fingerprint, _ = result
                finding.issues.extend(grade_key(finding.key_type, finding.bits, min_rsa_bits))
            else:
                finding.issues.append(
                    Issue("LOW", "could not fingerprint private key; algorithm and size were not checked")
                )
            if mismatch is not None:
                finding.issues.append(mismatch)

            finding.issues.extend(check_private_key_perms(path, expected_uid=user.pw_uid))
            if encrypted is False:
                sev = "HIGH" if user.pw_uid == 0 else "MEDIUM"
                finding.issues.append(Issue(sev, "private key has no passphrase"))
            elif encrypted is None:
                finding.issues.append(Issue("LOW", "could not determine whether the key is passphrase-protected"))
            findings.append(finding)
    return findings


# --------------------------------------------------------------------------- #
# Orchestration + output
# --------------------------------------------------------------------------- #


def run_audit(min_rsa_bits: int, do_host: bool, do_authorized: bool, do_private: bool) -> Report:
    """Run the selected sections and assemble a Report."""
    config, config_source, sshd_error = read_effective_sshd_config()
    server_issues, coverage = audit_server_config(config, config_source, sshd_error)

    host_keys = audit_host_keys(config, min_rsa_bits) if do_host else []
    host_key_paths = set(config.get("hostkey") or DEFAULT_HOST_KEYS)

    patterns: list[str] = []
    files: list[FileFinding] = []
    keys: list[AuthorizedKeyFinding] = []
    duplicates: dict[str, list[str]] = {}
    if do_authorized:
        # sshd -T alone shows the config with no Match block applied, so ask
        # sshd again per account to pick up Match User / Match Group changes.
        user_config: Callable[[pwd.struct_passwd], dict[str, list[str]] | None] | None = None
        if config_source == "sshd -T":
            sshd_bin = _find_sshd()
            if sshd_bin is not None:

                def read_for_user(user: pwd.struct_passwd) -> dict[str, list[str]] | None:
                    return read_user_sshd_config(user.pw_name, sshd_bin)

                user_config = read_for_user
        patterns, files, keys, duplicates, ak_coverage = audit_authorized_keys(
            config, min_rsa_bits, user_config=user_config
        )
        coverage.extend(ak_coverage)

    private_keys = audit_private_keys(min_rsa_bits, host_key_paths) if do_private else []

    return Report(
        config_source=config_source,
        effective_authorized_keys_file=patterns,
        coverage_warnings=coverage,
        server_config_issues=server_issues,
        host_keys=host_keys,
        authorized_key_files=files,
        authorized_keys=keys,
        duplicate_authorized_keys=duplicates,
        private_keys=private_keys,
    )


def _print_issues(issues: list[Issue], indent: str = "  ") -> None:
    for issue in sorted(issues, key=lambda i: SEVERITY_ORDER[i.severity]):
        print(f"{indent}[{issue.severity}] {issue.message}")


def _worst(issues: list[Issue]) -> int:
    return min((SEVERITY_ORDER[i.severity] for i in issues), default=len(SEVERITY_ORDER))


def _print_key_entry(k: AuthorizedKeyFinding) -> None:
    print(f"  line {k.line_number}: {k.key_type} {k.bits}-bit  {k.fingerprint}  {k.comment or '(no comment)'}")
    if k.options:
        print(f"    options: {','.join(k.options)}")
    _print_issues(k.issues, indent="    ") if k.issues else print("    ok")


def print_report(report: Report, verbose: bool = False) -> None:
    """Human-readable report.

    By default only files and keys with findings are listed. With ``verbose``
    every host key, every authorized_keys file and entry, and every private
    key is listed, grouped by file in file order, with ``ok`` for clean ones.
    """
    print(f"sshd config source: {report.config_source}")
    if report.coverage_warnings:
        print("\n=== Coverage warnings ===")
        for w in report.coverage_warnings:
            print(f"  ! {w}")

    if report.server_config_issues:
        print("\n=== Server configuration ===")
        _print_issues(report.server_config_issues)

    if report.host_keys:
        print(f"\n=== Host keys ({len(report.host_keys)}) ===")
        shown_host_keys = report.host_keys if verbose else [hk for hk in report.host_keys if hk.issues]
        for hk in shown_host_keys:
            line = f"\n{hk.path}"
            if hk.fingerprint:
                line += f"\n  {hk.key_type} {hk.bits}-bit  {hk.fingerprint}"
            print(line)
            _print_issues(hk.issues) if hk.issues else print("  ok")
        if not shown_host_keys:
            print("  no findings")

    if report.effective_authorized_keys_file or report.authorized_key_files:
        n_files, n_keys = len(report.authorized_key_files), len(report.authorized_keys)
        print(f"\n=== authorized_keys ({n_files} file(s), {n_keys} key(s)) ===")
        print(f"AuthorizedKeysFile: {' '.join(report.effective_authorized_keys_file) or 'none'}")
        if verbose:
            keys_by_file: dict[str, list[AuthorizedKeyFinding]] = defaultdict(list)
            for k in report.authorized_keys:
                keys_by_file[k.file_path].append(k)
            for f in report.authorized_key_files:
                print(f"\n{f.user}: {f.file_path} ({f.key_count} key(s))")
                _print_issues(f.issues)
                for k in sorted(keys_by_file[f.file_path], key=lambda k: k.line_number):
                    _print_key_entry(k)
        else:
            for f in (f for f in report.authorized_key_files if f.issues):
                print(f"\n{f.user}: {f.file_path} ({f.key_count} key(s))")
                _print_issues(f.issues)
            key_issues = sorted((k for k in report.authorized_keys if k.issues), key=lambda k: _worst(k.issues))
            for k in key_issues:
                print(f"\n{k.user}: {k.file_path}:{k.line_number}")
                print(f"  {k.key_type} {k.bits}-bit  {k.fingerprint}  {k.comment or '(no comment)'}")
                if k.options:
                    print(f"  options: {','.join(k.options)}")
                _print_issues(k.issues)
            if not key_issues and not any(f.issues for f in report.authorized_key_files):
                print("  no findings")

    if report.private_keys:
        print(f"\n=== Private keys in ~/.ssh ({len(report.private_keys)}) ===")
        shown_private_keys = report.private_keys if verbose else [pk for pk in report.private_keys if pk.issues]
        for pk in sorted(shown_private_keys, key=lambda p: _worst(p.issues)):
            print(f"\n{pk.user}: {pk.path}")
            desc = f"{pk.key_type} {pk.bits}-bit  {pk.fingerprint}" if pk.fingerprint else "(unfingerprinted)"
            if pk.encrypted is True:
                passphrase_desc = "passphrase-protected"
            elif pk.encrypted is False:
                passphrase_desc = "NO passphrase"
            else:
                passphrase_desc = "passphrase: unknown"
            print(f"  {desc}  {passphrase_desc}")
            _print_issues(pk.issues) if pk.issues else print("  ok")
        if not shown_private_keys:
            print("  no findings")

    counts: dict[str, int] = defaultdict(int)
    all_issues = (
        report.server_config_issues
        + [i for hk in report.host_keys for i in hk.issues]
        + [i for f in report.authorized_key_files for i in f.issues]
        + [i for k in report.authorized_keys for i in k.issues]
        + [i for p in report.private_keys for i in p.issues]
    )
    for i in all_issues:
        counts[i.severity] += 1
    summary = "  ".join(f"{sev}: {counts[sev]}" for sev in SEVERITY_ORDER if counts[sev])
    print(f"\nTotals: {summary or 'no issues'}")


def main(argv: list[str] | None = None) -> None:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        prog="audit-ssh-keys", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--min-rsa-bits",
        type=int,
        default=DEFAULT_MIN_RSA_BITS,
        help=(
            f"RSA keys below this size are flagged MEDIUM (default: {DEFAULT_MIN_RSA_BITS}); "
            "below 2048 is always CRITICAL"
        ),
    )
    parser.add_argument("--json", action="store_true", help="Emit the full report as JSON")
    parser.add_argument("--skip-host", action="store_true", help="Skip host key checks")
    parser.add_argument("--skip-authorized", action="store_true", help="Skip authorized_keys checks")
    parser.add_argument("--skip-private", action="store_true", help="Skip ~/.ssh private key checks")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="List every key, not just those with findings (text output)"
    )
    parser.add_argument("--debug", action="store_true", help="Debug logging to stderr")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING, format="%(levelname)s: %(message)s")

    if shutil.which("ssh-keygen") is None:
        raise AuditError("ssh-keygen not found; install openssh-client")
    if os.geteuid() != 0:
        print(
            "Warning: not running as root. Other users' files and host private keys will be "
            "skipped, and 'sshd -T' will fail so the effective config may be guessed.",
            file=sys.stderr,
        )

    report = run_audit(
        args.min_rsa_bits,
        do_host=not args.skip_host,
        do_authorized=not args.skip_authorized,
        do_private=not args.skip_private,
    )
    if args.json:
        print(json.dumps(asdict(report), indent=2))
    else:
        print_report(report, verbose=args.verbose)


def run() -> None:
    """Console-script wrapper: turn AuditError into a clean non-zero exit."""
    try:
        main()
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    run()
