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
import glob
import json
import logging
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
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
    # Post-quantum hybrid signature key, added to sshd's default HostKey list in
    # OpenSSH 10.x (pathnames.h's _PATH_HOST_MLDSA44_ED25519_KEY_FILE, servconf.c).
    "/etc/ssh/ssh_host_mldsa44_ed25519_key",
    "/etc/ssh/ssh_host_dsa_key",  # not a modern default, but audit it if present
]
SSHD_CONFIG = Path("/etc/ssh/sshd_config")
# Where sshd looks for the files named by a relative Include argument. This is
# the directory sshd was compiled with, and it does not change when sshd is
# pointed at another config file with -f, so it is not derived from SSHD_CONFIG.
SSHD_CONFIG_DIR = Path("/etc/ssh")
# How many levels of Include an sshd_config may nest; sshd's own limit.
MAX_INCLUDE_DEPTH = 16

# Signature algorithm names in sshd's *Algorithms lists that should not be accepted.
WEAK_SIG_ALGORITHMS = {
    "ssh-dss": "DSA signatures",
    "ssh-dss-cert-v01@openssh.com": "DSA certificate signatures",
    "ssh-rsa": "RSA with SHA-1 signatures",
    "ssh-rsa-cert-v01@openssh.com": "RSA certificate with SHA-1 signatures",
}

# First and last line of a key file in OpenSSH's own private key format.
OPENSSH_PRIVATE_KEY_HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----"
OPENSSH_PRIVATE_KEY_FOOTER = "-----END OPENSSH PRIVATE KEY-----"

PRIVATE_KEY_HEADERS = (
    OPENSSH_PRIVATE_KEY_HEADER,
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
)

# The same markers as raw bytes. A private key file is ASCII from end to end,
# so the code that asks "does this file start with a private-key header?"
# compares bytes rather than decoded text: decoding first answers from a header
# line that is not the one in the file. A stray byte replaced with U+FFFD stops
# the line looking like a header at all -- sending a corrupt key of a format
# this tool can check down the path meant for the formats it cannot -- while a
# stray byte dropped joins the text on either side of it into a header line
# that was never there.
OPENSSH_PRIVATE_KEY_HEADER_BYTES = OPENSSH_PRIVATE_KEY_HEADER.encode("ascii")
PRIVATE_KEY_HEADERS_BYTES = tuple(header.encode("ascii") for header in PRIVATE_KEY_HEADERS)

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
    when the file format was not recognised, so it could not be determined.
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
# Filesystem helpers
# --------------------------------------------------------------------------- #


def _stat_if_present(path: Path) -> os.stat_result | None:
    """stat() a path, returning None when nothing is there.

    Raises OSError for every other failure (permission denied on a directory
    above it, a symlink loop, a dead mount) so the caller can report that the
    path could not be checked instead of treating it as absent. Path.is_file()
    cannot be used for this: on Python 3.13 and later it answers False to a
    permission error, and on earlier versions it raises, so the tool would
    behave differently depending on the interpreter it happens to run under.
    """
    try:
        return path.stat()
    except (FileNotFoundError, NotADirectoryError):
        return None


def _is_regular_file(path: Path) -> bool:
    """True when path exists and is a regular file. Raises OSError when that could not be checked."""
    st = _stat_if_present(path)
    return st is not None and stat.S_ISREG(st.st_mode)


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
    values. When sshd isn't installed or -T fails, falls back to a naive parse
    of sshd_config, following Include directives in place the way sshd does;
    ignores Match blocks.
    """
    config: dict[str, list[str]] = defaultdict(list)
    sshd_error = ""

    sshd = sshd_bin if sshd_bin is not None else _find_sshd()
    if sshd:
        try:
            proc = subprocess.run([sshd, "-T"], capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL)
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

    # Fallback: naive parse of the config files themselves, Includes and all
    # (see _parse_sshd_config_file).
    if config_paths is None:
        config_paths = [SSHD_CONFIG]
    for cfg in config_paths:
        _parse_sshd_config_file(cfg, config)
    return dict(config), "parsed sshd_config (sshd -T unavailable)", sshd_error


def _split_config_args(text: str) -> list[str] | None:
    """Split the argument part of one sshd_config line into arguments, the way sshd does.

    This mirrors sshd's argv_split() (misc.c), which sshd calls with
    terminate_on_comment set when it reads a config file:

    - spaces and tabs separate arguments, and any run of them is skipped;
    - a `#` that starts an argument ends the line, so everything from there on
      is a comment; a `#` anywhere inside an argument is an ordinary character;
    - single and double quotes group text and are removed, so an argument can
      hold a space;
    - a backslash escapes a single quote, a double quote, another backslash,
      or -- outside quotes -- a space; any other backslash is kept as itself;
    - a quote that is never closed makes sshd refuse the whole config.

    Returns the arguments, or None for that unclosed-quote case, so the caller
    can skip a line sshd itself would not accept.
    """
    args: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        if text[index] in " \t":
            index += 1
            continue
        if text[index] == "#":
            break
        # Start of an argument: collect characters until unquoted whitespace
        # or the end of the line.
        quote = ""
        chars: list[str] = []
        while index < length:
            char = text[index]
            if char == "\\":
                following = text[index + 1] if index + 1 < length else ""
                if following in ("'", '"', "\\") or (not quote and following == " "):
                    index += 1
                    chars.append(text[index])
                else:
                    # Not an escape sshd recognises, so the backslash is just
                    # a character in the argument.
                    chars.append(char)
            elif not quote and char in " \t":
                break
            elif not quote and char in "\"'":
                quote = char
            elif quote and char == quote:
                quote = ""
            else:
                chars.append(char)
            index += 1
        args.append("".join(chars))
        if index >= length:
            if quote:
                return None
            break
    return args


def _expand_config_tilde(argument: str) -> str:
    """Expand a leading '~' in a config argument to a home directory, as sshd does.

    sshd passes an AuthorizedKeysFile argument through
    tilde_expand_filename(arg, getuid()) (servconf.c), and a HostKey argument
    through derelativise_path(), which calls the same function. A leading '~'
    on its own, or followed by '/', stands for the home directory of whoever
    runs sshd -- normally root -- and not for the home directory of the account
    whose keys are being audited; this fallback parser uses the home directory
    of whoever is running the audit, which is the closest it can get. A '~name'
    argument names that account's home directory instead, which is the same for
    sshd and for this tool.

    sshd expands '~' for several other filename settings too
    (AuthorizedPrincipalsFile, TrustedUserCAKeys, RevokedKeys, PidFile and
    HostKeyAgent). This tool never opens those files -- it only echoes their
    values back into coverage warnings -- so it does not expand them either,
    and the warning shows the path as the config file writes it.
    """
    if not argument.startswith("~"):
        return argument
    name, _, rest = argument[1:].partition("/")
    if name:
        try:
            home = pwd.getpwnam(name).pw_dir
        except KeyError:
            # sshd gives up on the whole config here ("No such user"), so
            # there is no right answer; the argument is kept as written.
            logger.debug("no such account %s, so %s is left unexpanded", name, argument)
            return argument
    else:
        try:
            home = pwd.getpwuid(os.getuid()).pw_dir
        except KeyError:
            # No passwd entry for the uid this process is running as, which
            # happens inside a container started with an arbitrary uid. sshd
            # gives up on the whole config in that case too, so as above the
            # argument is kept as written.
            logger.debug("no passwd entry for uid %s, so %s is left unexpanded", os.getuid(), argument)
            return argument
    # sshd joins the home directory and the rest of the path with a single '/',
    # which leaves a trailing '/' on a bare '~'.
    return home.rstrip("/") + "/" + rest.lstrip("/")


def _derelativise_config_path(argument: str) -> str:
    """Expand a leading '~' in a HostKey argument and make a relative path absolute, as sshd does.

    sshd passes each HostKey argument through derelativise_path() (servconf.c),
    which expands '~' and then joins a path that is still relative onto the
    directory sshd was started in. Nothing records that directory, so this
    fallback can only use the directory the audit is running in, which is very
    likely a different one; a relative HostKey path is rare for that reason.
    """
    # derelativise_path() checks for "none" before it touches anything else,
    # and leaves it alone (it returns the literal lowercase "none"; the value
    # is kept as written here so the report shows what the file says).
    if argument.lower() == "none":
        return argument
    expanded = _expand_config_tilde(argument)
    if expanded.startswith("/"):
        return expanded
    # Joined onto the current directory without collapsing any '..' in it,
    # which is what sshd does too.
    return str(Path.cwd() / expanded)


def _parse_sshd_config_file(path: Path, config: dict[str, list[str]], depth: int = 0) -> None:
    """Read one sshd_config file into config, following the Include directives in it.

    Keeps the first value seen for each keyword, except HostKey, which
    accumulates -- the same rule sshd uses. Match blocks are not evaluated, so
    everything from the first Match line to the end of the file is skipped,
    including any Include inside it. A file that is missing or unreadable is
    skipped. depth counts how many Includes deep this file is; nesting stops at
    MAX_INCLUDE_DEPTH, which is also what stops a file that includes itself.

    Each line's arguments are split the way sshd splits them (see
    _split_config_args), so a trailing comment is dropped, quotes and
    backslash escapes are honoured, and a line sshd would reject over an
    unclosed quote is skipped here too. The arguments are stored joined back
    together with single spaces, which is how `sshd -T` prints them as well.
    """
    try:
        if not _is_regular_file(path):
            return
    except OSError:
        # Could not even tell whether the file is there (for example, a
        # directory above it that this account cannot read). It already
        # returns silently for a file that exists but cannot be read, so do
        # the same here rather than raising out of a best-effort fallback.
        return
    try:
        # An sshd_config file may legitimately hold non-ASCII bytes (in a
        # Banner path or a comment, say), so a byte that does not decode is
        # replaced with U+FFFD rather than dropped: dropping it would join the
        # text on either side of it into something that was never in the file.
        # The encoding is named rather than left to the locale: what this file
        # holds is a property of the file, so the audit must not change with
        # the LANG the operator happens to be running under.
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    in_match = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # sshd's strdelim_internal() (misc.c) ends the keyword at the first
        # whitespace or '=', then skips the whitespace around it -- and skips
        # one '=' as well, but only if the keyword did not already end at one.
        # So "Keyword=value", "Keyword = value" and "Keyword =value" all mean
        # the same thing, while "Keyword==value" leaves a value of "=value",
        # which sshd then refuses ("unsupported option"). Whichever character
        # ended the keyword has to be remembered to tell those apart.
        keyword_split = re.match(r"([^\s=]*)(\s+|=)(.*)", line)
        if keyword_split is None:
            continue
        key = keyword_split.group(1).lower()
        rest = keyword_split.group(3).lstrip()
        if keyword_split.group(2) != "=" and rest.startswith("="):
            rest = rest[1:].lstrip()
        if key == "match":
            # Decide this before looking at the value, because the value is not
            # used for Match and a Match line sshd would reject -- an unclosed
            # quote, say -- still opens a block as far as this parser's reading
            # of the rest of the file goes. Going on to read the block's body
            # as global configuration would be much worse than skipping it:
            # a Match-block AuthorizedKeysFile would become the global pattern
            # and no account's real file would ever be scanned.
            in_match = True
            continue
        arguments = _split_config_args(rest)
        if arguments is None:
            # sshd refuses the whole config over an unclosed quote ("invalid
            # quotes"), so there is nothing sensible to read on this line.
            logger.debug("ignoring line with an unclosed quote in %s: %s", path, line)
            continue
        if not arguments:
            # Nothing but a comment after the keyword. sshd refuses a config
            # with a keyword that has no argument, so do not invent a value.
            logger.debug("ignoring %s line with no argument in %s", key, path)
            continue
        if key == "authorizedkeysfile":
            arguments = [_expand_config_tilde(argument) for argument in arguments]
        elif key == "hostkey":
            arguments = [_derelativise_config_path(argument) for argument in arguments]
        value = " ".join(arguments)
        if in_match:
            continue
        if key == "include":
            # Read the included files here, where the Include line sits, rather
            # than after the rest of this file. It matters because the first
            # value seen for a keyword is the one that counts: a drop-in
            # included near the top of a file beats a value set further down in
            # that same file. That is how the stock Ubuntu config works -- its
            # Include line comes before everything else, so a setting in
            # /etc/ssh/sshd_config.d wins over the rest of sshd_config.
            if depth >= MAX_INCLUDE_DEPTH:
                logger.debug("ignoring Include in %s: more than %s levels deep", path, MAX_INCLUDE_DEPTH)
                continue
            # The arguments were already split the way sshd splits them, so a
            # path with a space in it can be quoted, and a line with an
            # unclosed quote was skipped above.
            for argument in arguments:
                # sshd leaves an argument that starts with / or ~ alone (it
                # does not expand ~, and neither does glob below) and prefixes
                # anything else with its config directory. Each argument may be
                # a shell glob pattern, and the files it matches are read in
                # sorted order. Path.glob cannot do this: the whole pattern is
                # one string here, and is usually an absolute path, which
                # Path.glob refuses.
                pattern = argument if argument.startswith(("/", "~")) else str(SSHD_CONFIG_DIR / argument)
                for match in sorted(glob.glob(pattern)):  # noqa: PTH207
                    _parse_sshd_config_file(Path(match), config, depth + 1)
            continue
        if key == "hostkey" or key not in config:
            config.setdefault(key, []).append(value)


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
    the caller then falls back to the global configuration for that account
    and records a coverage warning saying so.
    """
    try:
        proc = subprocess.run(
            [sshd_bin, "-T", "-C", f"user={user_name}"],
            capture_output=True,
            text=True,
            check=False,
            stdin=subprocess.DEVNULL,
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


def _without_none(patterns: list[str]) -> list[str]:
    """A parsed AuthorizedKeysFile value with every 'none' entry (any case) dropped.

    sshd's user_key_allowed() loop (auth2-pubkey.c) checks each
    AuthorizedKeysFile entry against "none" with strcasecmp and skips just
    that entry, not only when the whole value is "none" -- so
    "none .ssh/authorized_keys2" scans authorized_keys2 and skips a file
    actually named "none".

    That is how every released sshd behaves, including 10.2, which starts
    happily with "none" listed alongside other entries. OpenSSH's current
    development code (servconf.c) refuses such a configuration outright
    instead, so a future sshd will not start on it at all; a value that mixes
    "none" with other entries gets a coverage warning saying so (see
    _mixed_none_warning).
    """
    return [p for p in patterns if p.lower() != "none"]


def _mixed_none_warning(value: str, user_name: str | None = None) -> str:
    """The coverage line for an AuthorizedKeysFile value listing 'none' next to real paths.

    value is the configured AuthorizedKeysFile value, echoed back to the
    operator so they can see which setting is meant. user_name is None for the
    global setting, and otherwise the account whose own effective value came
    from a Match block.
    """
    whose = "" if user_name is None else f" for {user_name} (Match block)"
    return (
        f"AuthorizedKeysFile mixes 'none' with other entries{whose} ({value}); "
        "released sshd versions skip just the 'none' entry and this audit does the same, "
        "but OpenSSH's current development code rejects the whole configuration, "
        "so a future upgrade may stop sshd from starting."
    )


def home_dir(user: pwd.struct_passwd) -> Path:
    """The directory to treat as an account's home for filesystem lookups.

    An empty pw_dir field (a real, if unusual, passwd entry) means the
    filesystem root to sshd and to login -- not the current working directory
    of whatever process happens to be looking, which is what plain
    Path(user.pw_dir) would resolve to when pw_dir is "".
    """
    return Path(user.pw_dir or "/")


def expand_authorized_keys_pattern(pattern: str, user: pwd.struct_passwd) -> str:
    """Expand sshd AuthorizedKeysFile tokens (%%, %h, %u, %U) for one account.

    This has to match sshd's percent_expand() (misc.c), which makes a single
    left-to-right pass over the pattern: each %x token is replaced by its
    value and the scan continues right after the inserted text, so that text
    is never itself rescanned for more tokens. Chained str.replace() calls
    get this wrong -- replacing %h with the home directory and then, as a
    separate step, replacing %u/%U anywhere in the string would also expand
    a %u or %U that the home directory itself happens to contain.
    """

    def repl(match: re.Match[str]) -> str:
        token = match.group(1)
        if token == "%":
            return "%"
        if token == "h":
            return user.pw_dir
        if token == "u":
            return user.pw_name
        if token == "U":
            return str(user.pw_uid)
        # sshd rejects any other %token while loading the config, so this
        # tool never sees one; left untouched rather than raising, just in case.
        return match.group(0)

    path = re.sub(r"%(.)", repl, pattern)
    if not path.startswith("/"):
        path = str(home_dir(user) / path)
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


def _fingerprint_private_file_alone(path: Path) -> tuple[str, int, str, str] | None:
    """Fingerprint a private key file with any `.pub` sibling hidden from ssh-keygen.

    `ssh-keygen -lf <path>` does not read `<path>` when a `<path>.pub` file
    exists next to it -- it silently reads that `.pub` file instead, even one
    with a different key inside it (verified against OpenSSH 10.2: the loader
    tries the `.pub` file before ever opening the private key). Pointing
    ssh-keygen at the private key in place would therefore just echo whatever
    `.pub` happens to be sitting there, which defeats the whole point of
    checking the private key for real.

    To get ssh-keygen to look at the private key itself, this creates a
    throwaway, private (mode 0700) temporary directory, puts a symlink to the
    private key's absolute path inside it, and runs ssh-keygen on the symlink.
    Nothing beside the symlink lives in that directory, so there is no `.pub`
    file for ssh-keygen to find, and it has no choice but to open the private
    key. No key material is ever copied -- only a symlink is created, and the
    directory (symlink included) is removed immediately afterward.

    Returns None when ssh-keygen cannot read the key at all (it is
    passphrase-protected, or the file is owned by the account running this tool
    with any group or other permission bits set, which makes ssh-keygen refuse
    to open it),
    or when the temporary directory or symlink cannot be created; the caller
    then falls back to the `.pub` file, exactly as for a passphrase-protected
    key.
    """
    try:
        tmpdir = tempfile.TemporaryDirectory()
    except OSError as exc:
        logger.debug("could not create a temporary directory to fingerprint %s: %s", path, exc)
        return None
    with tmpdir:
        link = Path(tmpdir.name) / "key"
        try:
            link.symlink_to(path.absolute())
        except OSError as exc:
            logger.debug("could not fingerprint %s through a temporary symlink: %s", path, exc)
            return None
        # Deliberately outside the try: a failure in here means ssh-keygen is
        # missing or unusable, which must not be quietly read as "this key
        # needs a passphrase" and turned into a fall back to the `.pub` file.
        return fingerprint_file(link)


def _ssh_keygen_would_refuse(path: Path) -> bool:
    """True when ssh-keygen would turn this private key file down over its permissions.

    `sshkey_perm_ok()` in ssh's authfile.c refuses a key file when the account
    running the program owns it and it has any group or other permission bits
    set: `st.st_uid == getuid() && (st.st_mode & 077) != 0`. That is every bit,
    not just the read bits -- mode 0601 and mode 0610 are turned down as surely
    as 0644 is. A file owned by someone else is read fine, which is why root
    auditing another account's world-readable key is not affected.

    Returns True when the file cannot be stat'd either: there is then no way to
    tell, so the caller must not count on ssh-keygen being able to read it.
    """
    try:
        st = path.stat()
    except OSError as exc:
        logger.debug("could not stat %s to tell whether ssh-keygen would read it: %s", path, exc)
        return True
    return st.st_uid == os.getuid() and bool(stat.S_IMODE(st.st_mode) & 0o077)


def _ssh_can_load_private_key(path: Path) -> bool:
    """True when ssh itself can load the private half of this key file.

    `ssh-keygen -l` cannot answer this: handed a private key file in the
    current OpenSSH format it reads the public half out of it and writes the
    private half's failure to its debug log only (verified against OpenSSH
    10.2), so a file whose private half is corrupt still prints a fingerprint.
    `ssh-keygen -y` has to load the private half for real, since it derives
    the public key from it -- so it is the one cheap, read-only way to ask ssh
    whether this is a file it can use. For a file in the current OpenSSH format,
    that runs ssh's own loader: the two check integers have to match, every
    private field has to deserialize, and the padding has to run 1, 2, 3, ...
    The public key it prints is discarded; nothing is written anywhere, and the
    file itself is not touched.

    An empty passphrase is handed over with `-P` so that the command can never
    stop to ask for one. Closing stdin is not enough on its own here:
    ssh-keygen reads a passphrase from /dev/tty, so a run from a terminal would
    otherwise hang. Callers only ask about keys with no passphrase set, and
    `-P ""` keeps a key that turns out to have one from blocking the run --
    such a key simply answers False.

    The output is collected as bytes, not text. `ssh-keygen -y` prints the
    key's comment alongside the public key exactly as the bytes sit in the
    file, and a comment holding a byte that is not valid UTF-8 (a name typed
    in Latin-1, say) would make decoding it raise and abort the whole audit.
    Only the exit status is wanted here, so the output is never decoded.
    """
    proc = subprocess.run(
        ["ssh-keygen", "-y", "-P", "", "-f", str(path)],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    return proc.returncode == 0


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


def _stripped_lines(path: Path) -> list[str] | None:
    """Read a private key file and return its non-blank lines with surrounding whitespace removed.

    A private key file is ASCII from its first line to its last: marker lines,
    base64, and (in the legacy PEM formats) plain headers. It is decoded
    strictly, so a single byte that is not ASCII means this is not the key file
    it claims to be. Dropping such a byte instead would let the base64 on
    either side of it join up and decode as though the byte had never been
    there, reporting a file OpenSSH refuses to load as a healthy key.

    Returns None when the file cannot be read, or when it is not ASCII.
    """
    try:
        text = path.read_bytes().decode("ascii")
    except (OSError, UnicodeDecodeError):
        return None
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _openssh_private_key_lines(path: Path) -> list[str] | None:
    """Read a file's stripped, non-blank lines if it is a complete OpenSSH-format private key.

    Returns None when the file cannot be read, when its first non-blank line is
    not the OpenSSH private-key header (for example a PEM/PKCS#8 key, or
    anything that is not a key at all), or when its last non-blank line is not
    the matching footer -- a missing footer means the file was cut short, and
    ssh cannot load a key that stops partway through.
    """
    lines = _stripped_lines(path)
    if not lines or lines[0] != OPENSSH_PRIVATE_KEY_HEADER or lines[-1] != OPENSSH_PRIVATE_KEY_FOOTER:
        return None
    return lines


def _is_openssh_format(path: Path) -> bool:
    """True when the file's first non-blank line starts with the OpenSSH private-key header.

    Used to tell a corrupt OpenSSH-format key (which must be reported as
    unfingerprintable, not confused with whatever `.pub` file happens to sit
    next to it) apart from the older PEM/PKCS#8 formats, where falling back
    to a `.pub` file is the intended behaviour. Only the start of the first
    line is checked, so a file that is in this format but damaged -- cut short
    before its footer line, or with junk stuck on the end of the header line
    itself -- still counts as an attempt at this format, which is what keeps
    it from falling back to a `.pub` file that says nothing about it.
    `public_key_from_private` holds the damaged file to the full format (an
    exact header line, ASCII throughout) and answers None for it, so such a
    file is reported as unfingerprintable rather than as the `.pub` file's key.

    The comparison is on raw bytes rather than on decoded text. Decoding the
    file first -- with undecodable bytes replaced -- would make a single stray
    byte in the header line itself answer False, which is exactly the fallback
    to an unrelated `.pub` file this check exists to prevent. Returns False
    when the file cannot be read at all.
    """
    try:
        raw = path.read_bytes()
    except OSError as exc:
        logger.debug("could not read %s to tell whether it is in the OpenSSH key format: %s", path, exc)
        return False
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped.startswith(OPENSSH_PRIVATE_KEY_HEADER_BYTES)
    return False


def _openssh_key_blob(path: Path) -> bytes | None:
    """Decode an OpenSSH-format private key file and return everything after the magic string.

    Returns None when the file cannot be read, is not in OpenSSH's own private
    key format, stops before its closing "-----END OPENSSH PRIVATE KEY-----"
    line, or its base64 body is corrupt or does not start with the expected
    "openssh-key-v1" marker.
    """
    lines = _openssh_private_key_lines(path)
    if lines is None:
        return None
    # Only the header and footer lines are markers; anything else that looks like
    # one is part of the base64 body. Dropping it instead of decoding it would
    # silently repair a corrupt file that OpenSSH itself refuses to load.
    body = "".join(lines[1:-1])
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

    Returns None for anything that is not an OpenSSH-format private key, and
    for any such file that ssh itself would not load: one truncated anywhere --
    in its public half, in the private half that follows it, or at the footer
    line -- one claiming any number of keys other than one, and one carrying
    extra bytes after the private half. A key ssh cannot load must not be
    reported as a healthy key.
    """
    blob = _openssh_key_blob(path)
    if blob is None:
        return None
    try:
        _cipher, offset = _read_string(blob, 0)
        _kdf, offset = _read_string(blob, offset)
        _kdf_options, offset = _read_string(blob, offset)
        nkeys, offset = _read_uint32(blob, offset)
        if nkeys != 1:
            # The format can hold a count other than one, but ssh itself only
            # loads single-key files, so no other count is a usable key.
            return None
        public_blob, offset = _read_string(blob, offset)
        # The private half comes last. Its contents are not read here (they are
        # encrypted when the key has a passphrase), but it has to be there in
        # full: a file that stops inside it is one ssh cannot load.
        _private_data, end = _read_string(blob, offset)
        if end != len(blob):
            # ssh refuses a file with bytes after the private half. (The padding
            # that rounds the key out sits inside that half, not after it.)
            return None
        key_type, _ = _read_string(public_blob, 0)
        name = key_type.decode("ascii")
    except ValueError:  # UnicodeDecodeError is a ValueError subclass
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

    For an unencrypted key in the current OpenSSH format the private half is
    checked as well, by asking ssh-keygen to derive the public key from it
    (`_ssh_can_load_private_key`) -- work only the private half can do, so no
    `.pub` file can answer for it. ssh builds the key it actually uses out of
    that half, and a public half that reads cleanly says nothing about whether
    the private half is intact, so this runs ssh's own loader over the file:
    the two check integers have to match, every private field has to
    deserialize, and the padding has to run 1, 2, 3, ... What that catches is
    any file ssh's own loader cannot load: mismatched check integers, private
    fields that do not deserialize, bad padding, or a body mangled in transit
    (CRLF line endings, indentation). A file that fails any
    of that is one ssh cannot load, and is reported as unfingerprintable (the
    same LOW `could not fingerprint` finding a corrupt public half gets). When
    it passes, the embedded public half is still the answer reported; for any
    file ssh-keygen itself wrote, the two agree. A file gets only the checks on
    its public half, so corruption inside its private half goes undetected,
    when it is passphrase-protected (it cannot be loaded at all without the
    passphrase), when ssh-keygen would refuse it over its permissions (the
    account running this tool owns it and it has any group or other permission
    bits set), or when the file cannot be stat'd to tell which of those is the
    case.

    The fallbacks below apply only to keys in the older PEM/PKCS#8 formats,
    which do not carry a readable public half. For those, the private key
    file itself is fingerprinted first (through the symlink trick in
    `_fingerprint_private_file_alone`, which keeps ssh-keygen from being
    steered by a stale `.pub`). Only when the private file cannot be read at
    all -- it is passphrase-protected, or it is owned by the account running
    this tool with any group or other permission bits set, which makes
    ssh-keygen refuse to open it -- is the `.pub` file used instead, and in that case a stale
    `.pub` cannot be detected: there is nothing to compare it against. A key
    in the current OpenSSH format whose embedded public half cannot be read,
    or can be read but not fingerprinted, is corrupt, and is reported as
    unfingerprintable no matter what `.pub` file sits next to it -- that file
    says nothing about which key this one is.
    """
    line = public_key_from_private(path)
    result = fingerprint_line(line) if line else None
    if result is None and _is_openssh_format(path):
        # A key in this format carries its public half in the clear, so either
        # that half is missing or it is there and unreadable -- a corrupt file
        # either way, not merely an old format. Whatever `.pub` file sits
        # beside it could describe any other key, so it gets no say here.
        return None, None

    # True only for a key in the current OpenSSH format -- the one format with
    # an embedded public half to have read -- that ssh-keygen can open: not
    # passphrase-protected, and not turned down over its permissions.
    ssh_can_load_it_if_intact = (
        result is not None and private_key_is_encrypted(path) is False and not _ssh_keygen_would_refuse(path)
    )
    if ssh_can_load_it_if_intact and not _ssh_can_load_private_key(path):
        # The public half being intact says nothing about the private half ssh
        # actually builds the key from, so ask ssh itself: ssh-keygen goes
        # through ssh's own loader and succeeds only for a file ssh can load.
        # That turns down mismatched check integers, private fields that do not
        # deserialize, bad padding, and a body mangled in transit (CRLF line
        # endings, indentation).
        return None, None

    if result is None:
        # No readable embedded public half: a legacy PEM/PKCS#8 key. Try the
        # private key file itself first -- it is the authoritative answer
        # whenever ssh-keygen can read it at all.
        result = _fingerprint_private_file_alone(path)

    pub = pub_sibling(path)
    try:
        # A .pub file this tool cannot even stat is treated the same as no
        # .pub file at all: there is nothing to compare the private key against.
        pub_result = fingerprint_file(pub) if _is_regular_file(pub) else None
    except OSError:
        pub_result = None

    mismatch: Issue | None = None
    if result is not None and pub_result is not None and result[2] != pub_result[2]:
        mismatch = Issue(
            "LOW",
            f"{pub.name} does not match this private key (public file is {pub_result[0]} {pub_result[2]})",
        )

    if result is None:
        # The private key itself could not be read (passphrase-protected, or
        # owned by the account running this tool with any group or other
        # permission bits set, which makes ssh-keygen refuse to open it):
        # fall back to the
        # .pub file, the only thing left that is readable. A stale .pub cannot
        # be detected here -- there is nothing to compare it against.
        result = pub_result
    return result, mismatch


def private_key_is_encrypted(path: Path) -> bool | None:
    """True if a passphrase is required, False if not, None if the format is unrecognised.

    Decided by inspecting the file rather than invoking ssh-keygen, so it works
    on keys ssh-keygen would refuse to load (for example, world-readable ones):

    * OpenSSH native format: the cipher name embedded after the magic string
      is ``none`` for unencrypted keys.
    * Legacy PEM (RSA/DSA/EC): a ``Proc-Type: 4,ENCRYPTED`` header.
    * PKCS#8: ``BEGIN ENCRYPTED PRIVATE KEY`` vs ``BEGIN PRIVATE KEY``.

    A private key file is ASCII throughout, so it is decoded strictly and a
    file holding any other byte is reported as unrecognised rather than having
    that byte dropped -- dropping it could make a corrupt body decode as a
    clean one, answering this question from bytes that are not in the file.
    """
    try:
        text = path.read_bytes().decode("ascii")
    except (OSError, UnicodeDecodeError):
        return None
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    header = lines[0]

    if header == OPENSSH_PRIVATE_KEY_HEADER:
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
    """Cheap header check so we only run ssh-keygen on plausible private keys.

    Compares the first 64 bytes against the header markers as bytes, for the
    same reason `_is_openssh_format` does: a private key file is ASCII from end
    to end, so the bytes in the file are the question being asked. Decoding the
    head first with undecodable bytes dropped would join the text on either
    side of such a byte back together, and answer from a header line that was
    never in the file.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(64)
    except OSError:
        return False
    return head.lstrip().startswith(PRIVATE_KEY_HEADERS_BYTES)


# --------------------------------------------------------------------------- #
# authorized_keys line parsing
# --------------------------------------------------------------------------- #


def _is_bare_key_line(stripped: str) -> bool:
    """True when an authorized_keys line starts with a key rather than with options.

    This is the same test sshd makes before it goes looking for options: the
    second field has to be base64 whose first item (a 4-byte length, then that
    many bytes) spells out the same type name as the first field. Every OpenSSH
    public key -- plain, certificate, security-key, and whatever is added next
    -- is built that way, so key types this tool has never heard of are still
    recognised, which a list of known type names could not do.
    """
    fields = stripped.split(None, 2)
    if len(fields) < 2:
        return False
    type_name, blob = fields[0], fields[1]
    try:
        raw = base64.b64decode(blob, validate=True)
        embedded, _ = _read_string(raw, 0)
        return embedded == type_name.encode("ascii")
    except (binascii.Error, ValueError, UnicodeEncodeError):
        # Not base64, too short to hold a length-prefixed string, or a type
        # name with non-ASCII characters in it: whatever this line is, it does
        # not start with a key.
        return False


def split_options(line: str) -> tuple[list[str], str]:
    """Split an authorized_keys line into (options, key-material-and-comment).

    Options are comma-separated and may contain quoted strings with commas or
    escaped quotes (e.g. command="foo,bar"). Inside a quoted value only \\" is
    an escape, the same rule _dequote_value() applies when it reads the value
    itself. A line whose second field is a key blob naming the same type as its
    first field has no options -- the same test sshd applies before it looks
    for options, so key types this tool has never seen still parse.
    """
    stripped = line.strip()
    if _is_bare_key_line(stripped):
        return [], stripped

    options: list[str] = []
    current: list[str] = []
    in_quotes = False
    i = 0
    while i < len(stripped):
        ch = stripped[i]
        if in_quotes:
            if ch == "\\" and i + 1 < len(stripped) and stripped[i + 1] == '"':
                # Only \" is an escape, exactly as sshd's opt_dequote() and
                # sshkey_advance_past_options() read it: a backslash in front
                # of anything else is a literal backslash and does not hide the
                # character after it. Skipping that character would close the
                # quote early and find a key on a line sshd throws out.
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


# Options that take no value. sshd accepts each of these on its own, and each
# of the second group with a "no-" in front of it as well; "no-restrict" and
# "no-cert-authority" are not accepted.
_FLAG_OPTIONS = ("restrict", "cert-authority")
_NEGATABLE_FLAG_OPTIONS = (
    "port-forwarding",
    "agent-forwarding",
    "x11-forwarding",
    "touch-required",
    "verify-required",
    "pty",
    "user-rc",
)
# Options that must be followed by = and a double-quoted string.
_VALUE_OPTIONS = (
    "command",
    "principals",
    "from",
    "expiry-time",
    "environment",
    "permitopen",
    "permitlisten",
    "tunnel",
)
# Of those, the ones sshd allows only once per line.
_SINGLE_USE_VALUE_OPTIONS = ("command", "principals", "from")
_ENV_NAME_RE = re.compile(r"[A-Za-z0-9_]+")
# sshd hands a tunnel= value to strtonum(), which calls strtoll(): leading
# whitespace is skipped and a leading sign is allowed, so " 5", "\t5", "-0",
# and "+7" all reach the range test below. Only the number that comes out has
# to be a device number sshd can use.
_TUN_NUMBER_RE = re.compile(r"[ \t\n\v\f\r]*[+-]?[0-9]+")
# sshd's SSH_TUNID_MAX: the two values above it are reserved for "any" and "error".
_TUN_DEVICE_MAX = 0x7FFFFFFF - 2


def _dequote_value(text: str) -> tuple[str, str] | str:
    """Read one double-quoted option value, the way sshd's opt_dequote() does.

    Returns (value, rest-of-the-text) on success, or the rejection reason as a
    string. Only \\" is an escape inside the quotes; a backslash in front of
    anything else is kept as a backslash, exactly as sshd keeps it.
    """
    if not text.startswith('"'):
        return "missing start quote"
    value: list[str] = []
    i = 1
    while i < len(text):
        if text[i] == '"':
            return "".join(value), text[i + 1 :]
        if text[i] == "\\" and i + 1 < len(text) and text[i + 1] == '"':
            value.append('"')
            i += 2
            continue
        value.append(text[i])
        i += 1
    return "missing end quote"


def check_options(options: list[str]) -> str | None:
    """Would sshd accept these authorized_keys options? None if yes, the reason if no.

    sshd's sshauthopt_parse() (auth-options.c) rejects the *whole* line when
    any option fails to parse -- it logs "bad key options: <reason>" and the
    key grants no access -- so a typo such as "no-port-fowarding" silently
    turns a working entry into a dead one. The reasons returned here are
    sshd's own wording, with the offending text added for an unknown option.

    Takes the option list produced by split_options(), where each element is
    one option ('no-pty' or 'command="a,b"').

    What is checked: the option names, the quoting of every value, the three
    clauses sshd allows only once (command, principals, from), the values of
    environment= and tunnel=, and that principals= appears only together with
    cert-authority. What is deliberately not checked: the contents of
    expiry-time=, permitopen=, and permitlisten= values, because whether those
    parse depends on the sshd version, on the machine's timezone and date
    handling, and on /etc/services lookups -- wrongly calling a working line
    dead would be worse than missing a broken one.
    """
    seen_single_use: set[str] = set()
    for option in options:
        unknown = f'unknown key option "{option}"'
        lowered = option.lower()

        name = next((f for f in _FLAG_OPTIONS if lowered.startswith(f)), None)
        if name is None:
            name = next(
                (f for f in _NEGATABLE_FLAG_OPTIONS if lowered.startswith(f) or lowered.startswith("no-" + f)),
                None,
            )
            if name is not None and lowered.startswith("no-"):
                name = "no-" + name
        if name is not None:
            # sshd matches the flag name as a prefix, then insists the next
            # character ends the option, so "pty=x" and "restricted" are both
            # rejected as unknown.
            if len(option) != len(name):
                return unknown
            continue

        name = next((v for v in _VALUE_OPTIONS if lowered.startswith(v + "=")), None)
        if name is None:
            return unknown
        if name in _SINGLE_USE_VALUE_OPTIONS:
            if name in seen_single_use:
                return f'multiple "{name}" clauses'
            seen_single_use.add(name)
        dequoted = _dequote_value(option[len(name) + 1 :])
        if isinstance(dequoted, str):
            return dequoted
        value, rest = dequoted
        if rest:
            # Text after the closing quote: sshd wants a comma, whitespace, or
            # the end of the line there.
            return unknown
        if name == "environment":
            env_name, sep, _ = value.partition("=")
            if not sep or not _ENV_NAME_RE.fullmatch(env_name):
                return "invalid environment string"
        elif name == "tunnel" and value.lower() != "any":
            if not _TUN_NUMBER_RE.fullmatch(value) or not 0 <= int(value) <= _TUN_DEVICE_MAX:
                return "invalid tun device"

    lowered_options = [o.lower() for o in options]
    if any(o.startswith("principals=") for o in lowered_options) and "cert-authority" not in lowered_options:
        # auth_authorise_keyopts() (auth2-pubkeyfile.c) denies a line whose
        # options name principals without also marking the key as a CA: the
        # principals list only means anything for certificates signed by it.
        # sshd checks this after the options have parsed, so this check does too.
        return "principals on non-CA key"
    return None


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

    # sshd's realpath("") on an empty pw_dir fails, so it walks all the way to
    # /; Path("") would otherwise resolve to the current working directory and
    # could make the walk stop there instead.
    home_real: Path | None = None
    if owner.pw_dir:
        home_path = Path(owner.pw_dir)
        try:
            home_present = _stat_if_present(home_path) is not None
        except OSError:
            # Could not tell whether the home directory is there -- for
            # example, another account's home when this tool is not running
            # as root. Treat it as absent: the walk below then continues all
            # the way to /, which is the conservative (stricter) behaviour.
            home_present = False
        if home_present:
            home_real = home_path.resolve()

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
    if cfg_value(config, "hostkeyagent", "none").lower() != "none":
        coverage.append(
            f"HostKeyAgent is set ({cfg_value(config, 'hostkeyagent', '')}); "
            "private host keys held by the agent are not on disk and cannot be audited."
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
    injectable (as the other audit functions take `users=`, `config_paths=`,
    `sshd_bin=`) so tests can run as an ordinary user and still exercise the
    ownership check without needing real root-owned files.
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
        try:
            present = _is_regular_file(path)
        except OSError as exc:
            findings.append(HostKeyFinding(str(path), "?", 0, "", [Issue("LOW", f"could not stat host key: {exc}")]))
            continue
        if not present:
            if config.get("hostkey"):
                # Explicitly configured but missing: sshd will log an error for it.
                findings.append(
                    HostKeyFinding(str(path), "?", 0, "", [Issue("LOW", "configured HostKey does not exist")])
                )
            continue

        if not looks_like_private_key(path):
            public = fingerprint_file(path)
            if public is not None:
                # A HostKey that names a public key file. sshd tries
                # sshkey_load_private() first, then sshkey_load_public()
                # (sshd.c): with HostKeyAgent set it logs "will rely on agent
                # for hostkey" and serves that key, and without one it cannot
                # load a private key at all. Either way the file holds no
                # private material, so the permission, passphrase and .pub
                # checks below have nothing to look at.
                key_type, bits, fingerprint, _ = public
                if _is_certificate(key_type):
                    # A certificate file, which sshd cannot use as a HostKey at
                    # all. The "will rely on agent for hostkey" path in sshd.c
                    # is only taken for a plain key type, so a HostKey naming a
                    # certificate fails even when the agent holds both the key
                    # and the certificate -- verified against OpenSSH 10.2,
                    # which logs "Unable to load host key" and then exits with
                    # "no hostkeys available". The host offers nothing from this
                    # line, so its type is not recorded as present and its
                    # algorithm and size are not graded.
                    findings.append(
                        HostKeyFinding(
                            str(path),
                            key_type,
                            bits,
                            fingerprint,
                            [
                                Issue(
                                    "LOW",
                                    "HostKey names a certificate file; sshd cannot load a host key from it "
                                    "(a certificate belongs on a HostCertificate line)",
                                )
                            ],
                        )
                    )
                    continue
                agent = cfg_value(config, "hostkeyagent", "none")
                if agent.lower() != "none":
                    finding = HostKeyFinding(
                        str(path),
                        key_type,
                        bits,
                        fingerprint,
                        [
                            Issue(
                                "INFO",
                                "public key file; the private half is held by HostKeyAgent and cannot be audited here",
                            )
                        ],
                    )
                    # sshd serves this key through the agent, so the host does
                    # offer this key type, and its algorithm and size still matter.
                    types_present.add(key_type.upper())
                    finding.issues.extend(grade_key(key_type, bits, min_rsa_bits))
                    findings.append(finding)
                else:
                    # No agent, so sshd has no usable key from this line at
                    # all: the type is deliberately not recorded as present,
                    # and the algorithm and size are deliberately not graded
                    # either, because sshd never offers this key to anyone.
                    findings.append(
                        HostKeyFinding(
                            str(path),
                            key_type,
                            bits,
                            fingerprint,
                            [
                                Issue(
                                    "LOW",
                                    "HostKey names a public key file and no HostKeyAgent is set; "
                                    "sshd cannot load a private key from it",
                                )
                            ],
                        )
                    )
                continue

        result, mismatch = fingerprint_private_key(path)
        if result is None:
            finding = HostKeyFinding(str(path), "?", 0, "", [Issue("LOW", "could not fingerprint host key")])
        else:
            key_type, bits, fingerprint, _ = result
            types_present.add(key_type.upper())
            finding = HostKeyFinding(str(path), key_type, bits, fingerprint)
            finding.issues.extend(grade_key(key_type, bits, min_rsa_bits))

        # These checks apply regardless of whether the key could be fingerprinted:
        # an unreadable or corrupt key can still be world-readable, wrongly owned,
        # or passphrase-protected, and sshd rejects it for those reasons too.
        if mismatch is not None:
            finding.issues.append(mismatch)
        perm_issues = check_private_key_perms(path, expected_uid=owner_uid)
        # sshkey_perm_ok() turns a private key down over its mode only when the
        # account running the program owns the file. sshd runs as root, so it
        # refuses a root-owned host key with group or other bits, and loads one
        # that belongs to somebody else whatever its mode says -- which leaves
        # that account, and anyone the mode admits, able to read and replace the
        # server's identity key. The owner issue check_private_key_perms()
        # produces is what says which case this is.
        wrong_owner = any(issue.message.startswith("owned by ") for issue in perm_issues)
        for issue in perm_issues:
            if "accessible" in issue.message:
                issue.message += (
                    "; sshd still loads it because root does not own it" if wrong_owner else "; sshd refuses to load it"
                )
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


def _is_certificate(key_type: str) -> bool:
    """True when a key type names a certificate: `ssh-keygen -l` labels one `<TYPE>-CERT`."""
    return key_type.upper().endswith("-CERT")


def _bad_options_issue(line_number: int, reason: str) -> Issue:
    """The finding for a line whose options sshd will not parse, so it ignores the whole line."""
    return Issue("LOW", f"line {line_number}: bad key options ({reason}); sshd rejects the whole line")


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
    account, in which case the global configuration is used for it and a
    coverage warning is recorded, since that account's own sshd -T -C
    user=<account> run could not be trusted.

    The returned pattern list is the global one, not any per-account override.
    """
    patterns = cfg_value(config, "authorizedkeysfile", " ".join(DEFAULT_AUTHORIZED_KEYS_PATTERNS)).split()
    coverage: list[str] = []
    remaining = _without_none(patterns)
    if not remaining and patterns:
        coverage.append("AuthorizedKeysFile is 'none'; sshd reads no authorized_keys files.")
    # 'none' listed next to real paths is a configuration this sshd accepts
    # and a future one will not, so it is worth a warning of its own -- once
    # for the global setting, not once per account.
    global_mixes_none = bool(remaining) and len(remaining) != len(patterns)
    if global_mixes_none:
        coverage.append(_mixed_none_warning(" ".join(patterns)))
    patterns = remaining

    files: list[FileFinding] = []
    keys: list[AuthorizedKeyFinding] = []
    fp_locations: dict[str, list[str]] = defaultdict(list)
    # Which accounts each key is authorized for. The same key listed twice for
    # one account is untidy but grants nothing extra, so it is graded lower
    # than the same key shared between two accounts.
    fp_users: dict[str, set[str]] = defaultdict(set)
    # (account, path): sshd consults a shared absolute path for every account,
    # so the same file has to be scanned once per account -- but a pattern
    # listed twice for one account is still only scanned once.
    seen_paths: set[tuple[str, str]] = set()
    # One ssh-keygen call per distinct key line, not per account that has it.
    fingerprints: dict[str, tuple[str, int, str, str] | None] = {}
    # Accounts whose own `sshd -T -C user=<name>` run failed. One coverage line
    # after the loop names all of them.
    config_failures: list[str] = []

    for user in sorted(users if users is not None else pwd.getpwall(), key=lambda u: u.pw_uid):
        user_patterns = patterns
        if user_config is not None:
            account_config = user_config(user)
            if account_config is not None:
                user_patterns = cfg_value(
                    account_config, "authorizedkeysfile", " ".join(DEFAULT_AUTHORIZED_KEYS_PATTERNS)
                ).split()
            else:
                # In production this means `sshd -T -C user=<name>` itself
                # failed, so the account's own Match blocks were never
                # consulted. Falling back to the global setting without
                # saying so would leave the report silently claiming
                # coverage it does not have. The names are gathered here and
                # reported as one line below: on a host where the per-account
                # run fails for everybody, a line per account would bury the
                # rest of the report.
                config_failures.append(user.pw_name)
        user_remaining = _without_none(user_patterns)
        if not user_remaining and user_patterns:
            # An account's effective AuthorizedKeysFile can be 'none' for two
            # different reasons: a Match block actually sets it for this one
            # account, or the global AuthorizedKeysFile is already 'none', in
            # which case `sshd -T -C user=X` just echoes that same 'none' for
            # every account. The global case already has its own coverage
            # line above; only add a per-account line for the Match-block
            # case, which is exactly when `patterns` (the global list) was
            # not itself emptied out by 'none'.
            if patterns:
                coverage.append(
                    f"AuthorizedKeysFile is 'none' for {user.pw_name} (Match block); "
                    "sshd reads no authorized_keys files for that account."
                )
            continue
        if len(user_remaining) != len(user_patterns) and not global_mixes_none:
            # Same reasoning as the 'none' line just above: a per-account run
            # echoes the global value, so only a Match block that mixes 'none'
            # in for this one account earns a line here. The global case
            # already has its own line above.
            coverage.append(_mixed_none_warning(" ".join(user_patterns), user.pw_name))
        user_patterns = user_remaining

        for pattern in user_patterns:
            path = Path(expand_authorized_keys_pattern(pattern, user))
            if (user.pw_name, str(path)) in seen_paths:
                continue
            try:
                present = _is_regular_file(path)
            except OSError as exc:
                # Could not even tell whether the file is there -- for example,
                # another account's home when this tool is not running as
                # root. That is different from the file being absent, so it
                # gets its own file-level finding instead of being skipped
                # silently.
                seen_paths.add((user.pw_name, str(path)))
                files.append(
                    FileFinding(
                        user=user.pw_name,
                        file_path=str(path),
                        key_count=0,
                        issues=[Issue("LOW", f"could not stat {path}: {exc}")],
                    )
                )
                continue
            if not present:
                continue
            seen_paths.add((user.pw_name, str(path)))

            file_finding = FileFinding(user=user.pw_name, file_path=str(path), key_count=0)
            file_finding.issues.extend(check_strictmodes_path(path, user))

            try:
                # A comment field can hold whatever the person who wrote it
                # typed, so a byte that does not decode is replaced with
                # U+FFFD rather than dropped. In a comment that only changes
                # how the line is displayed; inside a key's base64 it makes
                # the blob unreadable, so the line is reported as unparseable
                # -- which is what sshd does with it too. The encoding is named
                # rather than left to the locale: what this file holds is a
                # property of the file, so the audit must not change with the
                # LANG the operator happens to be running under.
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError as exc:
                file_finding.issues.append(Issue("LOW", f"could not read file: {exc}"))
                files.append(file_finding)
                continue

            for idx, raw in enumerate(lines, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                options, key_material = split_options(line)
                if not key_material and options:
                    # split_options reads to the end of the line while a quote
                    # is still open, so a line such as `command="x ssh-ed25519
                    # AAAA...` leaves nothing behind that could be a key. sshd
                    # turns that line down over its options, not its key
                    # material, so report what sshd would actually complain
                    # about rather than calling the line unparseable.
                    option_problem = check_options(options)
                    if option_problem is not None:
                        file_finding.issues.append(_bad_options_issue(idx, option_problem))
                        continue
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
                # sshd throws the whole line away when the options do not
                # parse, so a line with a typo'd option name authorises
                # nobody. Counting it, or letting its key take part in the
                # reuse checks, would claim access that does not exist.
                option_problem = check_options(options)
                if option_problem is not None:
                    file_finding.issues.append(_bad_options_issue(idx, option_problem))
                    continue
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
                if _is_certificate(key_type):
                    # auth_check_authkey_line() (auth2-pubkeyfile.c) matches a plain
                    # presented key only against the line itself, and a presented
                    # certificate only against a cert-authority line holding the
                    # CA's plain key. A line whose own blob is a certificate --
                    # what ssh-keygen -l labels "<TYPE>-CERT" -- matches neither, so
                    # it never grants access; grading its size/algorithm or its
                    # options would wrongly imply it does something.
                    finding.issues.append(
                        Issue(
                            "INFO",
                            "certificate listed in authorized_keys; sshd never matches a certificate here, "
                            "so this line grants no access",
                        )
                    )
                else:
                    finding.issues.extend(grade_key(key_type, bits, min_rsa_bits))
                    finding.issues.extend(grade_options(options, user))
                    # Only plain keys go into the reuse maps. ssh-keygen -l
                    # reports a certificate under the fingerprint of the key
                    # inside it, so a certificate line here would look like
                    # that key authorised for this account as well -- and it
                    # authorises nothing at all.
                    fp_locations[fingerprint].append(f"{user.pw_name} {path}:{idx}")
                    fp_users[fingerprint].add(user.pw_name)
                keys.append(finding)

            files.append(file_finding)

    if config_failures:
        count = len(config_failures)
        coverage.append(
            f"could not read the effective sshd config for {count} account{'' if count == 1 else 's'} "
            f"(sshd -T -C user=<name> failed for: {', '.join(config_failures)}); Match blocks were not applied "
            f"to {'that account' if count == 1 else 'those accounts'} and the global AuthorizedKeysFile was "
            "used instead"
        )

    duplicates = {fp: locs for fp, locs in fp_locations.items() if len(locs) > 1}
    for finding in keys:
        if _is_certificate(finding.key_type):
            # A certificate carries the fingerprint of the key inside it, so it
            # would pick up a reuse note whenever that key is listed elsewhere,
            # even though this line grants nothing.
            continue
        locations = duplicates.get(finding.fingerprint)
        if locations is None:
            continue
        here = f"{finding.user} {finding.file_path}:{finding.line_number}"
        others = [loc for loc in locations if loc != here]
        if len(fp_users[finding.fingerprint]) > 1:
            finding.issues.append(Issue("MEDIUM", f"same key also authorized at: {', '.join(others)}"))
        else:
            # One account, several entries: whoever holds the private key could
            # already log into this account, so nothing extra is granted. It
            # still matters, because deleting one entry does not revoke the key.
            finding.issues.append(
                Issue(
                    "LOW",
                    f"same key also listed for this account at: {', '.join(others)}; "
                    "removing one entry does not revoke it",
                )
            )

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
        ssh_dir = home_dir(user) / ".ssh"
        try:
            st = _stat_if_present(ssh_dir)
        except OSError as exc:
            # Could not even tell whether ~/.ssh is there -- for example,
            # another account's home when this tool is not running as root.
            # Skip it the same way an unreadable ~/.ssh already is (see the
            # except OSError around iterdir() below); the start-of-run
            # warning already tells the operator that non-root runs miss
            # other accounts' files.
            logger.debug("could not stat %s: %s", ssh_dir, exc)
            continue
        if st is None or not stat.S_ISDIR(st.st_mode) or str(ssh_dir) in seen:
            continue
        seen.add(str(ssh_dir))
        try:
            entries = sorted(p for p in ssh_dir.iterdir() if p.is_file() and not p.is_symlink())
        except OSError:
            continue

        for path in entries:
            if str(path) in host_key_paths or not looks_like_private_key(path):
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
            keys_by_account_file: dict[tuple[str, str], list[AuthorizedKeyFinding]] = defaultdict(list)
            for k in report.authorized_keys:
                keys_by_account_file[k.user, k.file_path].append(k)
            for f in report.authorized_key_files:
                print(f"\n{f.user}: {f.file_path} ({f.key_count} key(s))")
                _print_issues(f.issues)
                for k in sorted(keys_by_account_file[f.user, f.file_path], key=lambda k: k.line_number):
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
