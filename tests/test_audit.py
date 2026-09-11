"""Tests for permission checks and the host-key, authorized_keys, and private-key sections.

These generate real keys with ssh-keygen and lay out fake home directories
under tmp_path, then feed fake passwd entries to the audit functions.
"""

from __future__ import annotations

import base64
import json
import os
import pwd
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

import pytest

from audit_ssh_keys import audit
from tests.conftest import USER_UID, make_user, mkdir_clean, needs_root, needs_ssh_keygen, pub

pytestmark = needs_ssh_keygen


def _by_sev(issues: list[audit.Issue]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for i in issues:
        out.setdefault(i.severity, []).append(i.message)
    return out


def _write_ak(user: pwd.struct_passwd, lines: list[str], mode: int = 0o600) -> Path:
    ssh_dir = Path(user.pw_dir) / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    ak = ssh_dir / "authorized_keys"
    ak.write_text("\n".join(lines) + "\n")
    ak.chmod(mode)
    return ak


# --- check_strictmodes_path -------------------------------------------------


def test_strictmodes_clean_layout_has_no_issues(current_user_at: pwd.struct_passwd):
    ak = _write_ak(current_user_at, ["# empty"])
    Path(current_user_at.pw_dir).chmod(0o755)
    assert audit.check_strictmodes_path(ak, current_user_at) == []


def test_strictmodes_644_and_755_are_accepted(current_user_at: pwd.struct_passwd):
    # sshd only cares about write bits for group/other, not read bits.
    ak = _write_ak(current_user_at, ["# empty"], mode=0o644)
    ak.parent.chmod(0o755)
    assert audit.check_strictmodes_path(ak, current_user_at) == []


@pytest.mark.parametrize("target", ["file", "ssh_dir", "home"])
def test_strictmodes_group_writable_anywhere_in_path_is_high(current_user_at: pwd.struct_passwd, target: str):
    ak = _write_ak(current_user_at, ["# empty"])
    victim = {"file": ak, "ssh_dir": ak.parent, "home": Path(current_user_at.pw_dir)}[target]
    victim.chmod(victim.stat().st_mode | 0o020)
    issues = audit.check_strictmodes_path(ak, current_user_at)
    assert [i.severity for i in issues] == ["HIGH"]
    assert str(victim) in issues[0].message
    assert "writable" in issues[0].message


def test_strictmodes_world_writable_is_high(current_user_at: pwd.struct_passwd):
    ak = _write_ak(current_user_at, ["# empty"], mode=0o666)
    issues = audit.check_strictmodes_path(ak, current_user_at)
    assert [i.severity for i in issues] == ["HIGH"]


def test_strictmodes_root_owned_is_fine(tmp_path: Path):
    # Files created by root for another account are accepted by sshd.
    alice = make_user("alice", 65534, tmp_path)  # some uid other than the creator's
    ak = _write_ak(alice, ["# empty"])
    issues = audit.check_strictmodes_path(ak, alice)
    if os.getuid() == 0:
        assert issues == []
    else:
        # Creator is neither alice nor root, so ownership is flagged for all three paths.
        assert all(i.severity == "HIGH" and "owned by" in i.message for i in issues)
        assert len(issues) == 3


@needs_root
def test_strictmodes_wrong_owner_is_high(tmp_path: Path):
    alice = make_user("alice", 65531, tmp_path)
    ak = _write_ak(alice, ["# empty"])
    os.chown(ak, 65532, 65532)
    issues = audit.check_strictmodes_path(ak, alice)
    assert len(issues) == 1
    assert issues[0].severity == "HIGH"
    assert "owned by 65532" in issues[0].message


def test_owner_phrase_collapses_for_root():
    assert audit._owner_phrase(0) == "root"


def test_owner_phrase_names_a_non_root_uid():
    if os.getuid() == 0:
        pytest.skip("current uid is root; this covers the non-root case")
    name = pwd.getpwuid(os.getuid()).pw_name
    assert audit._owner_phrase(os.getuid()) == f"{name} or root"


def test_strictmodes_owner_phrase_collapses_for_root(tmp_path: Path):
    """When the expected owner is root, the message says 'not root', not the redundant 'not root or root'."""
    if os.getuid() == 0:
        pytest.skip("running as root: the file is already root-owned, no mismatch to observe")
    root_owner = make_user("root", 0, tmp_path)
    ak = _write_ak(root_owner, ["# empty"])
    tmp_path.chmod(0o755)

    issues = audit.check_strictmodes_path(ak, root_owner)
    assert issues
    assert all(i.severity == "HIGH" and "not root" in i.message and "not root or root" not in i.message for i in issues)


def test_strictmodes_missing_file_is_low(tmp_path: Path):
    alice = make_user("alice", os.getuid(), tmp_path)
    issues = audit.check_strictmodes_path(tmp_path / ".ssh" / "authorized_keys", alice)
    assert [i.severity for i in issues] == ["LOW"]
    assert "could not resolve" in issues[0].message


def test_strictmodes_unstattable_path_is_low(tmp_path: Path):
    """A path the tool cannot stat is LOW, not a silent pass."""
    alice = make_user("alice", os.getuid(), tmp_path)
    issues = audit._check_one_strictmodes_path(tmp_path / "gone", alice)
    assert [i.severity for i in issues] == ["LOW"]
    assert "could not stat" in issues[0].message


def _reported_path(issue: audit.Issue) -> Path:
    """The path an owner/mode message is about: every such message starts with '<path> is '."""
    return Path(issue.message.split(" is ", 1)[0])


def _assert_only_victim_and_tmp_ancestors(issues: list[audit.Issue], victim: Path, tmp_path: Path) -> None:
    """Allow findings about `victim` plus any about tmp_path and the directories above it.

    A file outside the account's home is checked all the way up to /, and
    pytest's tmp_path lives under /tmp, which is mode 1777. Those ancestors are
    real findings, not test noise: sshd really does refuse an authorized_keys
    file that sits under a world-writable directory.
    """
    top = tmp_path.resolve()
    for issue in issues:
        reported = _reported_path(issue)
        assert reported == victim or top.is_relative_to(reported), issue.message


def test_strictmodes_checks_every_directory_up_to_the_home(tmp_path: Path):
    """A pattern deeper than ~/.ssh still has ~/.ssh itself checked."""
    alice = make_user("alice", os.getuid(), tmp_path / "home" / "alice")
    key_dir = mkdir_clean(Path(alice.pw_dir) / ".ssh" / "keys", tmp_path)
    ak = key_dir / "authorized_keys"
    ak.write_text("# empty\n")
    ak.chmod(0o600)
    ssh_dir = Path(alice.pw_dir) / ".ssh"
    ssh_dir.chmod(0o775)

    issues = audit.check_strictmodes_path(ak, alice)
    assert [i.severity for i in issues] == ["HIGH"]
    assert str(ssh_dir.resolve()) in issues[0].message
    assert "group/world-writable" in issues[0].message


def test_strictmodes_absolute_path_outside_the_home_is_checked_to_the_root(tmp_path: Path):
    alice = make_user("alice", os.getuid(), tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    etc_ssh = mkdir_clean(tmp_path / "etc" / "ssh", tmp_path)
    mkdir_clean(etc_ssh / "ak", tmp_path)
    ak = etc_ssh / "ak" / "alice"
    ak.write_text("# empty\n")
    ak.chmod(0o600)
    etc_ssh.chmod(0o775)

    issues = audit.check_strictmodes_path(ak, alice)
    victim = etc_ssh.resolve()
    assert any(
        i.severity == "HIGH" and str(victim) in i.message and "group/world-writable" in i.message for i in issues
    )
    _assert_only_victim_and_tmp_ancestors(issues, victim, tmp_path)

    # tmp_path lives under /tmp, which is mode 1777 on any normal system: prove
    # the walk actually reaches / by asserting that finding is present, not
    # merely tolerating it.
    if stat.S_IMODE(Path("/tmp").stat().st_mode) & 0o022:
        assert any(_reported_path(i) == Path("/tmp") for i in issues)


def test_strictmodes_follows_symlinks_before_checking(tmp_path: Path):
    alice = make_user("alice", os.getuid(), tmp_path / "home" / "alice")
    ssh_dir = mkdir_clean(Path(alice.pw_dir) / ".ssh", tmp_path)
    target_dir = mkdir_clean(tmp_path / "target", tmp_path)
    target = target_dir / "ak"
    target.write_text("# empty\n")
    target.chmod(0o600)
    link = ssh_dir / "authorized_keys"
    link.symlink_to(target)
    target_dir.chmod(0o775)

    issues = audit.check_strictmodes_path(link, alice)
    victim = target_dir.resolve()
    assert any(
        i.severity == "HIGH" and str(victim) in i.message and "group/world-writable" in i.message for i in issues
    )
    _assert_only_victim_and_tmp_ancestors(issues, victim, tmp_path)


def test_strictmodes_stops_at_the_home_directory(tmp_path: Path):
    """A directory above the home is sshd's business, not this account's: the walk stops at the home."""
    alice = make_user("alice", os.getuid(), tmp_path / "home" / "alice")
    ssh_dir = mkdir_clean(Path(alice.pw_dir) / ".ssh", tmp_path)
    ak = ssh_dir / "authorized_keys"
    ak.write_text("# empty\n")
    ak.chmod(0o600)
    (tmp_path / "home").chmod(0o775)

    assert audit.check_strictmodes_path(ak, alice) == []


def test_strictmodes_empty_pw_dir_does_not_stop_the_walk_early(tmp_path: Path):
    """Path("") resolves to the cwd, so an empty pw_dir must not silently stop the walk there.

    make_user stringifies its home argument, so an empty Path("") can't be
    built through it (it would come out as "."). Build the passwd entry by
    hand instead, the way a real account with no home directory looks.
    """
    nohome = pwd.struct_passwd(("nohome", "x", os.getuid(), os.getuid(), "nohome", "", "/bin/sh"))
    victim = mkdir_clean(tmp_path / "x", tmp_path)
    ssh_dir = mkdir_clean(victim / ".ssh", tmp_path)
    ak = ssh_dir / "authorized_keys"
    ak.write_text("# empty\n")
    ak.chmod(0o600)
    victim.chmod(victim.stat().st_mode | 0o020)  # group-writable

    issues = audit.check_strictmodes_path(ak, nohome)
    victim_real = victim.resolve()
    assert any(
        i.severity == "HIGH" and str(victim_real) in i.message and "group/world-writable" in i.message for i in issues
    )
    _assert_only_victim_and_tmp_ancestors(issues, victim_real, tmp_path)


# --- check_private_key_perms ------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (0o600, []),
        (0o400, []),
        (0o640, ["HIGH"]),
        (0o660, ["HIGH"]),
        (0o604, ["CRITICAL"]),
        (0o644, ["CRITICAL"]),
        (0o666, ["CRITICAL"]),
    ],
)
def test_private_key_perms_modes(tmp_path: Path, mode: int, expected: list[str]):
    key = tmp_path / "key"
    key.write_text("x")
    key.chmod(mode)
    issues = audit.check_private_key_perms(key, expected_uid=os.getuid())
    assert [i.severity for i in issues] == expected


def test_private_key_perms_wrong_owner(tmp_path: Path):
    key = tmp_path / "key"
    key.write_text("x")
    key.chmod(0o600)
    issues = audit.check_private_key_perms(key, expected_uid=os.getuid() + 1)
    if os.getuid() == 0:
        assert issues == []  # root-owned keys are accepted for any account
    else:
        assert [i.severity for i in issues] == ["HIGH"]
        assert "owned by" in issues[0].message


@needs_root
def test_private_key_perms_wrong_owner_as_root(tmp_path: Path):
    key = tmp_path / "key"
    key.write_text("x")
    key.chmod(0o600)
    os.chown(key, 65532, 65532)
    issues = audit.check_private_key_perms(key, expected_uid=65531)
    assert [i.severity for i in issues] == ["HIGH"]
    assert "owned by 65532" in issues[0].message


def test_private_key_perms_owner_phrase_collapses_for_root(tmp_path: Path):
    """expected_uid=0 renders 'expected root', not the redundant 'expected root or root'."""
    key = tmp_path / "key"
    key.write_text("x")
    key.chmod(0o600)
    issues = audit.check_private_key_perms(key, expected_uid=0)
    if os.getuid() == 0:
        pytest.skip("running as root: the file is already root-owned, no mismatch to observe")
    assert len(issues) == 1
    assert "expected root" in issues[0].message
    assert "expected root or root" not in issues[0].message


# --- fingerprinting and encryption detection --------------------------------


def test_fingerprint_line_with_options(keys: dict[str, Path]):
    line = f'from="10.0.0.0/8",command="/bin/true" {pub(keys["ed25519"])}'
    _, key_material = audit.split_options(line)
    result = audit.fingerprint_line(key_material)
    assert result is not None
    assert result[0] == "ED25519"
    assert result[3] == "ed@test"


def test_fingerprint_line_garbage_is_none():
    assert audit.fingerprint_line("ssh-rsa notreallyakey garbage@x") is None


def test_fingerprint_file_pub_and_private_match(keys: dict[str, Path]):
    priv = keys["rsa4096"]
    from_pub = audit.fingerprint_file(priv.with_name(priv.name + ".pub"))
    from_priv = audit.fingerprint_file(priv)
    assert from_pub is not None and from_priv is not None
    assert from_pub[:3] == from_priv[:3] == ("RSA", 4096, from_pub[2])


def _ssh_string(payload: bytes) -> bytes:
    """One SSH wire-format string: a big-endian 32-bit length, then the bytes."""
    return len(payload).to_bytes(4, "big") + payload


def _openssh_key_file(path: Path, payload: bytes) -> Path:
    """Write a file that looks like an OpenSSH private key but carries an arbitrary body."""
    body = base64.b64encode(b"openssh-key-v1\x00" + payload).decode()
    path.write_text(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n")
    return path


def _pem_key(path: Path, passphrase: str = "") -> Path:
    """Generate an RSA key in the old PEM format, which has no readable public half."""
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", passphrase, "-f", str(path)],
        check=True,
        capture_output=True,
    )
    return path


def test_public_key_from_private_matches_the_pub_file(keys: dict[str, Path]):
    """Every generated key, passphrase-protected included, fingerprints the same from either source."""
    for name, priv in keys.items():
        line = audit.public_key_from_private(priv)
        assert line is not None, name
        from_private = audit.fingerprint_line(line)
        from_pub = audit.fingerprint_file(priv.with_name(priv.name + ".pub"))
        assert from_private is not None and from_pub is not None, name
        # Only the comment can differ: it lives in the encrypted part of the file.
        assert from_private[:3] == from_pub[:3], name


def test_public_key_from_private_works_on_world_readable_key(keys: dict[str, Path], tmp_path: Path):
    # ssh-keygen refuses to load a 0644 key, so this must not depend on it.
    copy = tmp_path / "id_ed25519"
    copy.write_bytes(keys["encrypted"].read_bytes())
    copy.chmod(0o644)
    line = audit.public_key_from_private(copy)
    assert line is not None
    result = audit.fingerprint_line(line)
    assert result is not None and result[0] == "ED25519"


def test_public_key_from_private_is_none_for_pem_and_non_keys(tmp_path: Path):
    assert audit.public_key_from_private(_pem_key(tmp_path / "pem")) is None
    not_a_key = tmp_path / "config"
    not_a_key.write_text("Host x\n  User y\n")
    assert audit.public_key_from_private(not_a_key) is None
    assert audit.public_key_from_private(tmp_path / "missing") is None


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        # A public-key blob whose promised length runs off the end of the file.
        (
            "truncated",
            _ssh_string(b"none")
            + _ssh_string(b"none")
            + _ssh_string(b"")
            + (1).to_bytes(4, "big")
            + (99).to_bytes(4, "big"),
        ),
        # Claims to hold no keys at all.
        ("no_keys", _ssh_string(b"none") + _ssh_string(b"none") + _ssh_string(b"") + (0).to_bytes(4, "big")),
        # Key type that is not ASCII.
        (
            "non_ascii_type",
            _ssh_string(b"none")
            + _ssh_string(b"none")
            + _ssh_string(b"")
            + (1).to_bytes(4, "big")
            + _ssh_string(_ssh_string(b"\xff\xfe")),
        ),
        # Empty key type.
        (
            "empty_type",
            _ssh_string(b"none")
            + _ssh_string(b"none")
            + _ssh_string(b"")
            + (1).to_bytes(4, "big")
            + _ssh_string(_ssh_string(b"")),
        ),
        # Nothing after the magic string at all.
        ("empty", b""),
    ],
)
def test_public_key_from_private_is_none_for_corrupt_bodies(tmp_path: Path, name: str, payload: bytes):
    assert audit.public_key_from_private(_openssh_key_file(tmp_path / name, payload)) is None


def test_fingerprint_private_key_prefers_the_private_key_over_a_stale_pub(keys: dict[str, Path], tmp_path: Path):
    key = tmp_path / "id_ed25519"
    key.write_bytes(keys["encrypted"].read_bytes())
    key.chmod(0o600)
    audit.pub_sibling(key).write_text(pub(keys["rsa2048"]) + "\n")

    result, mismatch = audit.fingerprint_private_key(key)
    assert result is not None and result[0] == "ED25519"
    assert mismatch is not None and mismatch.severity == "LOW"
    assert mismatch.message.startswith("id_ed25519.pub does not match this private key")
    assert "RSA" in mismatch.message


def test_fingerprint_private_key_matching_pub_reports_no_mismatch(keys: dict[str, Path], tmp_path: Path):
    key = tmp_path / "id_ed25519"
    key.write_bytes(keys["encrypted"].read_bytes())
    key.chmod(0o600)
    audit.pub_sibling(key).write_bytes(keys["encrypted"].with_name("encrypted.pub").read_bytes())

    result, mismatch = audit.fingerprint_private_key(key)
    assert result is not None and result[0] == "ED25519"
    assert mismatch is None


def test_fingerprint_private_key_falls_back_for_pem_keys(tmp_path: Path):
    plain = _pem_key(tmp_path / "plain")
    audit.pub_sibling(plain).unlink()
    result, mismatch = audit.fingerprint_private_key(plain)
    assert result is not None and result[:2] == ("RSA", 2048)
    assert mismatch is None

    encrypted = _pem_key(tmp_path / "encrypted_pem", passphrase="hunter2")
    audit.pub_sibling(encrypted).unlink()
    result, mismatch = audit.fingerprint_private_key(encrypted)
    assert result is None and mismatch is None


def test_fingerprint_private_key_falls_back_when_the_pub_sibling_is_unparsable(tmp_path: Path):
    """A PEM key with a garbage (not merely stale) .pub beside it must still fall back to the private key.

    An unparsable .pub file means ssh-keygen cannot read it, but the private
    key itself is unencrypted and readable, so ssh-keygen can fingerprint that
    directly -- the fallback must not be skipped just because a .pub file
    happens to exist.
    """
    plain = _pem_key(tmp_path / "plain")
    audit.pub_sibling(plain).write_text("not a key\n")
    result, mismatch = audit.fingerprint_private_key(plain)
    assert result is not None and result[:2] == ("RSA", 2048)
    assert mismatch is None


def test_private_key_is_encrypted(keys: dict[str, Path]):
    assert audit.private_key_is_encrypted(keys["ed25519"]) is False
    assert audit.private_key_is_encrypted(keys["encrypted"]) is True


def test_private_key_is_encrypted_works_on_world_readable_key(keys: dict[str, Path], tmp_path: Path):
    # ssh-keygen refuses to load a 0644 key, so detection must not depend on it.
    for name, expected in (("ed25519", False), ("encrypted", True)):
        copy = tmp_path / name
        copy.write_bytes(keys[name].read_bytes())
        copy.chmod(0o644)
        assert audit.private_key_is_encrypted(copy) is expected


@pytest.mark.parametrize(
    ("header", "extra", "expected"),
    [
        ("-----BEGIN RSA PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n", True),
        ("-----BEGIN RSA PRIVATE KEY-----", "", False),
        ("-----BEGIN EC PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED\n", True),
        ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "", True),
        ("-----BEGIN PRIVATE KEY-----", "", False),
        ("-----BEGIN CERTIFICATE-----", "", None),
    ],
)
def test_private_key_is_encrypted_pem_variants(tmp_path: Path, header: str, extra: str, expected: bool | None):
    key = tmp_path / "k"
    key.write_text(f"{header}\n{extra}AAAA\n-----END X-----\n")
    assert audit.private_key_is_encrypted(key) is expected


def test_private_key_is_encrypted_corrupt_openssh_body(tmp_path: Path):
    key = tmp_path / "k"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nnot base64!!\n-----END OPENSSH PRIVATE KEY-----\n")
    assert audit.private_key_is_encrypted(key) is None
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
    assert audit.private_key_is_encrypted(key) is None  # valid base64, wrong magic


def test_private_key_is_encrypted_truncated_cipher_field_is_none(tmp_path: Path):
    # cipher_len says 4 bytes follow, but only 2 are actually present: a truncated
    # file must not be misread as "cipher present" (and so classified as encrypted).
    magic = b"openssh-key-v1\x00"
    body = base64.b64encode(magic + (4).to_bytes(4, "big") + b"no").decode()
    key = tmp_path / "k"
    key.write_text(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n")
    assert audit.private_key_is_encrypted(key) is None


def test_private_key_is_encrypted_zero_length_cipher_field_is_none(tmp_path: Path):
    magic = b"openssh-key-v1\x00"
    body = base64.b64encode(magic + (0).to_bytes(4, "big")).decode()
    key = tmp_path / "k"
    key.write_text(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n")
    assert audit.private_key_is_encrypted(key) is None


def test_looks_like_private_key(keys: dict[str, Path], tmp_path: Path):
    assert audit.looks_like_private_key(keys["ed25519"]) is True
    assert audit.looks_like_private_key(keys["encrypted"]) is True
    pubfile = keys["ed25519"].with_name("ed25519.pub")
    assert audit.looks_like_private_key(pubfile) is False
    cfg = tmp_path / "config"
    cfg.write_text("Host foo\n  User bar\n")
    assert audit.looks_like_private_key(cfg) is False
    assert audit.looks_like_private_key(tmp_path / "missing") is False


# --- audit_host_keys ----------------------------------------------------------


def test_host_keys_from_config(keys: dict[str, Path], tmp_path: Path):
    rsa = tmp_path / "ssh_host_rsa_key"
    ed = tmp_path / "ssh_host_ed25519_key"
    rsa.write_bytes(keys["rsa2048"].read_bytes())
    rsa.with_suffix(".pub").write_bytes(keys["rsa2048"].with_name("rsa2048.pub").read_bytes())
    ed.write_bytes(keys["ed25519"].read_bytes())
    for p in (rsa, ed):
        p.chmod(0o600)
    rsa.chmod(0o644)

    config = {"hostkey": [str(rsa), str(ed), str(tmp_path / "missing")]}
    findings = audit.audit_host_keys(config, min_rsa_bits=3072, owner_uid=os.getuid())
    by_path = {f.path: f for f in findings}

    assert by_path[str(rsa)].key_type == "RSA" and by_path[str(rsa)].bits == 2048
    sev = _by_sev(by_path[str(rsa)].issues)
    assert any("below policy minimum" in m for m in sev["MEDIUM"])
    assert any("world-accessible" in m and "sshd refuses" in m for m in sev["CRITICAL"])

    assert by_path[str(ed)].key_type == "ED25519"
    assert by_path[str(ed)].issues == []

    assert [i.message for i in by_path[str(tmp_path / "missing")].issues] == ["configured HostKey does not exist"]
    assert "(none)" not in by_path  # an Ed25519 key is present, so no "missing Ed25519" entry


def test_host_keys_default_owner_is_root(keys: dict[str, Path], tmp_path: Path):
    """Without an injected owner_uid, a host key not owned by root is a HIGH."""
    if os.getuid() == 0:
        pytest.skip("running as root: the file IS root-owned, so there is no mismatch to observe")
    ed = tmp_path / "ssh_host_ed25519_key"
    ed.write_bytes(keys["ed25519"].read_bytes())
    ed.chmod(0o600)

    findings = audit.audit_host_keys({"hostkey": [str(ed)]}, min_rsa_bits=3072)
    by_path = {f.path: f for f in findings}
    assert by_path[str(ed)].issues == [audit.Issue("HIGH", f"owned by {audit.uid_name(os.getuid())}, expected root")]


def test_host_keys_missing_ed25519_is_noted(keys: dict[str, Path], tmp_path: Path):
    rsa = tmp_path / "ssh_host_rsa_key"
    rsa.write_bytes(keys["rsa4096"].read_bytes())
    rsa.chmod(0o600)
    findings = audit.audit_host_keys({"hostkey": [str(rsa)]}, min_rsa_bits=3072)
    assert any(f.path == "(none)" and "Ed25519" in f.issues[0].message for f in findings)


def test_host_keys_encrypted_key_is_low(keys: dict[str, Path], tmp_path: Path):
    enc = tmp_path / "ssh_host_ed25519_key"
    enc.write_bytes(keys["encrypted"].read_bytes())
    enc.with_suffix(".pub").write_bytes(keys["encrypted"].with_name("encrypted.pub").read_bytes())
    enc.chmod(0o600)
    findings = audit.audit_host_keys({"hostkey": [str(enc)]}, min_rsa_bits=3072)
    assert findings[0].fingerprint  # fingerprinted from the public half inside the private key file
    assert any(i.severity == "LOW" and "passphrase" in i.message for i in findings[0].issues)
    # The .pub sibling matches, so nothing is said about it.
    assert not any("does not match" in i.message for i in findings[0].issues)


def test_host_key_stale_pub_is_flagged_and_the_private_key_wins(keys: dict[str, Path], tmp_path: Path):
    """The .pub file next to a host key is only checked against the key, never trusted over it."""
    host_key = tmp_path / "ssh_host_ed25519_key"
    host_key.write_bytes(keys["encrypted"].read_bytes())
    host_key.chmod(0o600)
    audit.pub_sibling(host_key).write_text(pub(keys["rsa2048"]) + "\n")

    findings = audit.audit_host_keys({"hostkey": [str(host_key)]}, min_rsa_bits=3072, owner_uid=os.getuid())
    finding = next(f for f in findings if f.path == str(host_key))
    assert finding.key_type == "ED25519"
    mismatches = [i for i in finding.issues if i.severity == "LOW" and "does not match" in i.message]
    assert len(mismatches) == 1
    assert mismatches[0].message.startswith("ssh_host_ed25519_key.pub does not match this private key")


def test_host_keys_defaults_when_unconfigured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(audit, "DEFAULT_HOST_KEYS", [str(tmp_path / "nope")])
    # Unconfigured + missing default is silently skipped (no LOW), and no Ed25519 nag without any keys.
    assert audit.audit_host_keys({}, min_rsa_bits=3072) == []


# --- audit_authorized_keys ---------------------------------------------------


def test_authorized_keys_end_to_end(keys: dict[str, Path], tmp_path: Path):
    root = make_user("root", 0, tmp_path / "root")
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    svc = make_user("svc", USER_UID, tmp_path / "var" / "lib" / "svc")  # home outside /home
    for u in (root, alice, svc):
        Path(u.pw_dir).mkdir(parents=True, mode=0o755)

    _write_ak(
        alice,
        [
            "# managed by ansible",  # comment on line 1 must not swallow file-level findings
            pub(keys["rsa2048"]),
            f'from="10.0.0.0/8",command="/usr/bin/rsync --server",no-pty {pub(keys["ed25519"])}',
            "ssh-rsa notreallyakey garbage@x",
        ],
    )
    Path(alice.pw_dir).chmod(0o770)  # group-writable home
    _write_ak(svc, [pub(keys["rsa4096"]), pub(keys["ed25519"])])
    root_lines = [pub(keys["ed25519"]).rsplit(" ", 1)[0]]  # no comment, unrestricted
    if "dsa" in keys:
        root_lines.insert(0, pub(keys["dsa"]))
    _write_ak(root, root_lines)

    config = {"authorizedkeysfile": [".ssh/authorized_keys .ssh/authorized_keys2"]}
    patterns, files, ak, dupes, coverage = audit.audit_authorized_keys(config, 3072, users=[root, alice, svc])

    assert patterns == [".ssh/authorized_keys", ".ssh/authorized_keys2"]
    assert coverage == []
    assert {f.user for f in files} == {"root", "alice", "svc"}

    alice_file = next(f for f in files if f.user == "alice")
    assert alice_file.key_count == 2
    sev = _by_sev(alice_file.issues)
    assert any("group/world-writable" in m and str(alice.pw_dir) in m for m in sev["HIGH"])
    assert any(m.startswith("line 4: unparseable") for m in sev["LOW"])

    by_key = {(k.user, k.line_number): k for k in ak}
    assert _by_sev(by_key[("alice", 2)].issues) == {"MEDIUM": ["RSA 2048-bit is below policy minimum of 3072"]}
    restricted = by_key[("alice", 3)]
    assert restricted.options[0] == 'from="10.0.0.0/8"'
    assert "MEDIUM" in _by_sev(restricted.issues)  # duplicate
    assert "INFO" not in _by_sev(restricted.issues)  # non-root, restricted

    svc_strong = by_key[("svc", 1)]
    assert svc_strong.issues == []

    ed_fp = restricted.fingerprint
    assert set(dupes) == {ed_fp}
    assert len(dupes[ed_fp]) == 3
    root_ed = by_key[("root", len(root_lines))]
    assert root_ed.comment == ""
    sev = _by_sev(root_ed.issues)
    assert any("also authorized at" in m and "alice" in m and "svc" in m for m in sev["MEDIUM"])
    assert sev["INFO"] == ["uid-0 account key has no from= or command= restriction"]
    if "dsa" in keys:
        assert "HIGH" in _by_sev(by_key[("root", 1)].issues)


def test_authorized_keys_custom_absolute_pattern_and_dedup(keys: dict[str, Path], tmp_path: Path):
    alice = make_user("alice", os.getuid(), tmp_path / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    keydir = tmp_path / "etc" / "ssh" / "authorized_keys"
    mkdir_clean(keydir, tmp_path)
    (keydir / "alice").write_text(pub(keys["ed25519"]) + "\n")
    # Same path listed twice must only be scanned once.
    config = {"authorizedkeysfile": [f"{keydir}/%u {keydir}/%u"]}
    _, files, ak, dupes, _ = audit.audit_authorized_keys(config, 3072, users=[alice])
    assert [f.file_path for f in files] == [str(keydir / "alice")]
    assert len(ak) == 1
    assert dupes == {}


def test_authorized_keys_shared_absolute_file_is_attributed_to_every_account(
    keys: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """One literal AuthorizedKeysFile shared by every account: sshd reads it for all of them.

    Every key in it logs into every account, so it must be reported once per
    account and its keys must show up as reused across accounts.
    """
    root = make_user("root", 0, tmp_path / "root")
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    for u in (root, alice):
        mkdir_clean(Path(u.pw_dir), tmp_path)
    shared_dir = mkdir_clean(tmp_path / "etc" / "ssh", tmp_path)
    shared = shared_dir / "authorized_keys"
    shared.write_text(pub(keys["ed25519"]) + "\n" + pub(keys["rsa4096"]) + "\n")
    shared.chmod(0o644)

    calls: list[str] = []
    real_fingerprint_line = audit.fingerprint_line

    def counting(key_line: str):
        calls.append(key_line)
        return real_fingerprint_line(key_line)

    monkeypatch.setattr(audit, "fingerprint_line", counting)

    config = {"authorizedkeysfile": [str(shared)]}
    _, files, ak, dupes, _ = audit.audit_authorized_keys(config, 3072, users=[root, alice])

    assert [(f.user, f.file_path) for f in files] == [("root", str(shared)), ("alice", str(shared))]
    assert len(ak) == 4
    # Each distinct key line is fingerprinted once, not once per account.
    assert len(calls) == 2

    by_user_line = {(k.user, k.line_number): k for k in ak}
    assert set(by_user_line) == {("root", 1), ("root", 2), ("alice", 1), ("alice", 2)}
    assert len(dupes) == 2
    for line_no in (1, 2):
        fingerprint = by_user_line[("root", line_no)].fingerprint
        assert by_user_line[("alice", line_no)].fingerprint == fingerprint
        assert sorted(dupes[fingerprint]) == sorted([f"root {shared}:{line_no}", f"alice {shared}:{line_no}"])
        assert any(
            "also authorized at" in i.message and "alice" in i.message for i in by_user_line[("root", line_no)].issues
        )
        assert any(
            "also authorized at" in i.message and "root" in i.message for i in by_user_line[("alice", line_no)].issues
        )

    root_messages = [i.message for i in by_user_line[("root", 1)].issues]
    alice_messages = [i.message for i in by_user_line[("alice", 1)].issues]
    assert any("uid-0 account key has no from= or command= restriction" in m for m in root_messages)
    assert not any("uid-0" in m for m in alice_messages)


def test_authorized_keys_per_account_match_override(keys: dict[str, Path], tmp_path: Path):
    """A Match block that moves one account's AuthorizedKeysFile is honoured, and others keep the default."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID, tmp_path / "home" / "bob")
    for u in (alice, bob):
        mkdir_clean(Path(u.pw_dir), tmp_path)
    alice_ak = _write_ak(alice, [pub(keys["ed25519"])])
    custom = mkdir_clean(tmp_path / "etc" / "keys", tmp_path)
    bob_ak = custom / "bob"
    bob_ak.write_text(pub(keys["rsa4096"]) + "\n")
    bob_ak.chmod(0o600)

    def user_config(user: pwd.struct_passwd) -> dict[str, list[str]] | None:
        return {"authorizedkeysfile": [f"{custom}/%u"]} if user.pw_name == "bob" else None

    patterns, files, ak, _, coverage = audit.audit_authorized_keys(
        {}, 3072, users=[alice, bob], user_config=user_config
    )

    assert patterns == audit.DEFAULT_AUTHORIZED_KEYS_PATTERNS  # the returned list stays the global one
    assert {(f.user, f.file_path) for f in files} == {("alice", str(alice_ak)), ("bob", str(bob_ak))}
    assert {(k.user, k.key_type) for k in ak} == {("alice", "ED25519"), ("bob", "RSA")}
    assert coverage == []


def test_authorized_keys_match_none_skips_that_account_only(keys: dict[str, Path], tmp_path: Path):
    """AuthorizedKeysFile none inside a Match block: that account's files are not read."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID, tmp_path / "home" / "bob")
    for u in (alice, bob):
        mkdir_clean(Path(u.pw_dir), tmp_path)
    alice_ak = _write_ak(alice, [pub(keys["ed25519"])])
    _write_ak(bob, [pub(keys["rsa4096"])])

    def user_config(user: pwd.struct_passwd) -> dict[str, list[str]] | None:
        return {"authorizedkeysfile": ["none"]} if user.pw_name == "bob" else None

    _, files, ak, _, coverage = audit.audit_authorized_keys({}, 3072, users=[alice, bob], user_config=user_config)

    assert [(f.user, f.file_path) for f in files] == [("alice", str(alice_ak))]
    assert [k.user for k in ak] == ["alice"]
    assert len(coverage) == 1
    assert coverage[0].startswith("AuthorizedKeysFile is 'none' for bob (Match block)")


def test_authorized_keys_global_none_reports_coverage_once_not_per_account(keys: dict[str, Path], tmp_path: Path):
    """Global AuthorizedKeysFile none: sshd -T -C user=X echoes 'none' for every account too.

    That must not produce one false per-account coverage line per user on top
    of the one true global line.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID, tmp_path / "home" / "bob")
    carol = make_user("carol", USER_UID, tmp_path / "home" / "carol")

    def user_config(user: pwd.struct_passwd) -> dict[str, list[str]] | None:
        return {"authorizedkeysfile": ["none"]}

    patterns, files, ak, _, coverage = audit.audit_authorized_keys(
        {"authorizedkeysfile": ["none"]}, 3072, users=[alice, bob, carol], user_config=user_config
    )

    assert patterns == []
    assert files == []
    assert ak == []
    assert coverage == ["AuthorizedKeysFile is 'none'; sshd reads no authorized_keys files."]


def test_authorized_keys_none_pattern(tmp_path: Path):
    alice = make_user("alice", os.getuid(), tmp_path)
    patterns, files, ak, _, coverage = audit.audit_authorized_keys(
        {"authorizedkeysfile": ["none"]}, 3072, users=[alice]
    )
    assert patterns == [] and files == [] and ak == []
    assert coverage and "none" in coverage[0]


def test_authorized_keys_empty_file_still_reports_file_issues(tmp_path: Path):
    alice = make_user("alice", os.getuid(), tmp_path / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    ak = _write_ak(alice, ["# only a comment"], mode=0o666)
    _, files, findings, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])
    assert findings == []
    assert files[0].key_count == 0
    assert any(i.severity == "HIGH" and str(ak) in i.message for i in files[0].issues)


# --- audit_private_keys --------------------------------------------------------


def test_private_keys_end_to_end(keys: dict[str, Path], tmp_path: Path):
    alice = make_user("alice", USER_UID, tmp_path / "alice")
    root = make_user("root", 0, tmp_path / "root")
    for u in (alice, root):
        mkdir_clean(Path(u.pw_dir) / ".ssh", tmp_path)

    a_ssh = Path(alice.pw_dir) / ".ssh"
    (a_ssh / "id_ed25519").write_bytes(keys["encrypted"].read_bytes())
    (a_ssh / "id_ed25519.pub").write_bytes(keys["encrypted"].with_name("encrypted.pub").read_bytes())
    (a_ssh / "id_rsa_old").write_bytes(keys["rsa1024"].read_bytes())  # no .pub sibling
    (a_ssh / "config").write_text("Host x\n")
    (a_ssh / "known_hosts").write_text("x ssh-ed25519 AAAA\n")
    (a_ssh / "authorized_keys").write_text(pub(keys["ed25519"]) + "\n")
    for f in a_ssh.iterdir():
        f.chmod(0o600)
    (a_ssh / "id_rsa_old").chmod(0o644)

    r_ssh = Path(root.pw_dir) / ".ssh"
    (r_ssh / "id_ed25519").write_bytes(keys["ed25519"].read_bytes())
    (r_ssh / "id_ed25519").chmod(0o600)
    host_key = r_ssh / "ssh_host_ed25519_key"  # should be excluded as a host key
    host_key.write_bytes(keys["ed25519"].read_bytes())

    findings = audit.audit_private_keys(3072, host_key_paths={str(host_key)}, users=[alice, root])
    by_path = {f.path: f for f in findings}

    assert set(by_path) == {str(a_ssh / "id_ed25519"), str(a_ssh / "id_rsa_old"), str(r_ssh / "id_ed25519")}

    enc = by_path[str(a_ssh / "id_ed25519")]
    assert enc.encrypted is True
    # Read from the public half inside the private key file; the matching .pub sibling is silent.
    assert enc.fingerprint and enc.key_type == "ED25519"
    assert enc.issues == []

    old = by_path[str(a_ssh / "id_rsa_old")]
    assert old.encrypted is False
    # Fingerprinted from the public half inside the private key file; there is no .pub sibling.
    assert (old.key_type, old.bits) == ("RSA", 1024)
    sev = _by_sev(old.issues)
    assert len(sev["CRITICAL"]) == 2  # 1024-bit + world-accessible
    assert sev["MEDIUM"] == ["private key has no passphrase"]

    root_key = by_path[str(r_ssh / "id_ed25519")]
    sev = _by_sev(root_key.issues)
    assert "private key has no passphrase" in sev["HIGH"]


def _one_private_key(tmp_path: Path, write: Callable[[Path], None]) -> audit.PrivateKeyFinding:
    """Lay out a single-account ~/.ssh, let `write` fill it in, and audit it."""
    alice = make_user("alice", os.getuid(), tmp_path / "alice")
    a_ssh = mkdir_clean(Path(alice.pw_dir) / ".ssh", tmp_path)
    write(a_ssh)
    findings = audit.audit_private_keys(3072, host_key_paths=set(), users=[alice])
    assert len(findings) == 1
    return findings[0]


def test_private_key_stale_pub_is_flagged_and_the_private_key_wins(keys: dict[str, Path], tmp_path: Path):
    """A .pub file that belongs to a different key must not decide the reported type."""

    def write(a_ssh: Path) -> None:
        key = a_ssh / "id_ed25519"
        key.write_bytes(keys["encrypted"].read_bytes())
        key.chmod(0o600)
        (a_ssh / "id_ed25519.pub").write_text(pub(keys["rsa2048"]) + "\n")

    finding = _one_private_key(tmp_path, write)
    assert finding.key_type == "ED25519"
    lows = [i.message for i in finding.issues if i.severity == "LOW"]
    assert len([m for m in lows if m.startswith("id_ed25519.pub does not match")]) == 1


def test_private_key_encrypted_without_a_pub_is_still_fingerprinted(keys: dict[str, Path], tmp_path: Path):
    def write(a_ssh: Path) -> None:
        key = a_ssh / "id_ed25519"
        key.write_bytes(keys["encrypted"].read_bytes())
        key.chmod(0o600)

    finding = _one_private_key(tmp_path, write)
    assert finding.encrypted is True
    assert finding.key_type == "ED25519" and finding.fingerprint
    assert not any("could not fingerprint" in i.message for i in finding.issues)


def test_private_key_encrypted_pem_without_a_pub_cannot_be_fingerprinted(tmp_path: Path):
    """A passphrase-protected PEM key with no .pub file: say so rather than grade it silently."""

    def write(a_ssh: Path) -> None:
        key = _pem_key(a_ssh / "id_rsa", passphrase="hunter2")
        audit.pub_sibling(key).unlink()
        key.chmod(0o600)

    finding = _one_private_key(tmp_path, write)
    assert finding.encrypted is True
    assert (finding.key_type, finding.bits, finding.fingerprint) == ("?", 0, "")
    assert [i.severity for i in finding.issues] == ["LOW"]
    assert finding.issues[0].message == "could not fingerprint private key; algorithm and size were not checked"


def test_private_key_plain_pem_without_a_pub_is_fingerprinted(tmp_path: Path):
    def write(a_ssh: Path) -> None:
        key = _pem_key(a_ssh / "id_rsa")
        audit.pub_sibling(key).unlink()
        key.chmod(0o600)

    finding = _one_private_key(tmp_path, write)
    assert (finding.key_type, finding.bits) == ("RSA", 2048)
    assert not any("could not fingerprint" in i.message for i in finding.issues)


def test_private_keys_skips_symlinks_and_missing_dirs(keys: dict[str, Path], tmp_path: Path):
    alice = make_user("alice", os.getuid(), tmp_path / "alice")
    bob = make_user("bob", os.getuid(), tmp_path / "bob")  # no .ssh at all
    a_ssh = Path(alice.pw_dir) / ".ssh"
    mkdir_clean(a_ssh, tmp_path)
    (a_ssh / "link").symlink_to(keys["ed25519"])
    assert audit.audit_private_keys(3072, host_key_paths=set(), users=[alice, bob]) == []


def test_private_keys_unrecognised_body_reports_encrypted_as_none(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """A key with a plausible header but a body private_key_is_encrypted can't parse.

    must surface as encrypted=None ("unknown"), not be coerced to False, and
    the text report must say so rather than claiming "NO passphrase".
    """
    alice = make_user("alice", os.getuid(), tmp_path / "alice")
    a_ssh = Path(alice.pw_dir) / ".ssh"
    mkdir_clean(a_ssh, tmp_path)
    key = a_ssh / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nnot valid base64!!\n-----END OPENSSH PRIVATE KEY-----\n")
    key.chmod(0o600)

    findings = audit.audit_private_keys(3072, host_key_paths=set(), users=[alice])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.encrypted is None
    # The body is unreadable and there is no .pub sibling, so there is nothing to fingerprint from.
    assert finding.fingerprint == ""
    assert any(
        i.severity == "LOW" and i.message.startswith("could not fingerprint private key") for i in finding.issues
    )

    payload = json.dumps(asdict(finding))
    assert '"encrypted": null' in payload

    report = audit.Report(
        config_source="sshd -T",
        effective_authorized_keys_file=[],
        coverage_warnings=[],
        server_config_issues=[],
        host_keys=[],
        authorized_key_files=[],
        authorized_keys=[],
        duplicate_authorized_keys={},
        private_keys=[finding],
    )
    audit.print_report(report)
    out = capsys.readouterr().out
    assert "passphrase: unknown" in out
    assert "NO passphrase" not in out


# --- run_audit / print_report / CLI -----------------------------------------


def test_run_audit_and_report_smoke(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """Whole pipeline with an empty system: no crash, sane report, valid JSON."""
    cfg = tmp_path / "sshd_config"
    cfg.write_text("AuthorizedKeysFile none\nPasswordAuthentication no\n")
    monkeypatch.setattr(audit, "SSHD_CONFIG", cfg)
    monkeypatch.setattr(audit, "SSHD_CONFIG_D", tmp_path / "nope.d")
    monkeypatch.setattr(audit, "_find_sshd", lambda: None)
    monkeypatch.setattr(audit, "DEFAULT_HOST_KEYS", [str(tmp_path / "nokey")])
    monkeypatch.setattr(audit.pwd, "getpwall", lambda: [])

    report = audit.run_audit(3072, do_host=True, do_authorized=True, do_private=True)
    assert report.host_keys == [] and report.authorized_keys == [] and report.private_keys == []
    assert any("AuthorizedKeysFile is 'none'" in w for w in report.coverage_warnings)

    audit.print_report(report)
    out = capsys.readouterr().out
    assert "Coverage warnings" in out
    assert out.strip().endswith("Totals: no issues")

    audit.main(["--json", "--skip-host"])
    import json

    parsed = json.loads(capsys.readouterr().out)
    assert parsed["host_keys"] == []
    assert "coverage_warnings" in parsed


def test_main_without_ssh_keygen_raises(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(audit.shutil, "which", lambda _name: None)
    with pytest.raises(audit.AuditError):
        audit.main([])


def test_audit_py_runs_standalone_without_the_package(tmp_path: Path):
    """audit.py must still run when copied off by itself (docs/usage.md, "Fleet use").

    -S skips site-packages, so an installed copy of the package (which would
    make the `from audit_ssh_keys import __version__` import succeed even
    with PYTHONPATH stripped) cannot mask the standalone fallback either.
    """
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, "-S", audit.__file__, "--version"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "audit-ssh-keys unknown"


# --- verbose report ------------------------------------------------------------


def _report_with_one_clean_and_one_flagged_key(keys: dict[str, Path], tmp_path: Path) -> audit.Report:
    alice = make_user("alice", USER_UID, tmp_path / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [pub(keys["rsa4096"]), pub(keys["rsa2048"])])
    patterns, files, ak, dupes, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    host_keys = [
        audit.HostKeyFinding("/etc/ssh/ssh_host_ed25519_key_clean", "ED25519", 256, "SHA256:cleanhostkey"),
        audit.HostKeyFinding(
            "/etc/ssh/ssh_host_rsa_key_flagged",
            "RSA",
            2048,
            "SHA256:flaggedhostkey",
            issues=[audit.Issue("LOW", "example host key finding")],
        ),
    ]
    private_keys = [
        audit.PrivateKeyFinding(
            "alice", "/home/alice/.ssh/id_ed25519_clean", "ED25519", 256, "SHA256:cleanprivkey", False
        ),
        audit.PrivateKeyFinding(
            "alice",
            "/home/alice/.ssh/id_rsa_flagged",
            "RSA",
            2048,
            "SHA256:flaggedprivkey",
            False,
            issues=[audit.Issue("LOW", "example private key finding")],
        ),
    ]

    return audit.Report(
        config_source="sshd -T",
        effective_authorized_keys_file=patterns,
        coverage_warnings=[],
        server_config_issues=[],
        host_keys=host_keys,
        authorized_key_files=files,
        authorized_keys=ak,
        duplicate_authorized_keys=dupes,
        private_keys=private_keys,
    )


def test_default_report_lists_only_keys_with_findings(keys, tmp_path, capsys):
    report = _report_with_one_clean_and_one_flagged_key(keys, tmp_path)
    audit.print_report(report)
    out = capsys.readouterr().out
    assert "rsa2048@test" in out
    assert "rsa4096@test" not in out
    assert "  ok" not in out
    assert "ssh_host_ed25519_key_clean" not in out
    assert "ssh_host_rsa_key_flagged" in out
    assert "id_ed25519_clean" not in out
    assert "id_rsa_flagged" in out


def test_verbose_report_lists_every_key_grouped_by_file(keys, tmp_path, capsys):
    report = _report_with_one_clean_and_one_flagged_key(keys, tmp_path)
    audit.print_report(report, verbose=True)
    out = capsys.readouterr().out
    assert "rsa4096@test" in out and "rsa2048@test" in out
    assert "ssh_host_ed25519_key_clean" in out and "ssh_host_rsa_key_flagged" in out
    assert "id_ed25519_clean" in out and "id_rsa_flagged" in out
    # Grouped under the file header, in line order, clean key marked ok.
    lines = out.splitlines()
    i_file = next(i for i, ln in enumerate(lines) if ln.startswith("alice: ") and "authorized_keys" in ln)
    i_1 = next(i for i, ln in enumerate(lines) if ln.startswith("  line 1: RSA 4096-bit"))
    i_2 = next(i for i, ln in enumerate(lines) if ln.startswith("  line 2: RSA 2048-bit"))
    assert i_file < i_1 < i_2
    assert lines[i_1 + 1] == "    ok"
    assert lines[i_2 + 1].startswith("    [MEDIUM]")

    # Clean host key: path line, then "type bits fingerprint" line, then "  ok".
    i_host_clean = next(i for i, ln in enumerate(lines) if ln == "/etc/ssh/ssh_host_ed25519_key_clean")
    assert lines[i_host_clean + 2] == "  ok"

    # Clean private key: "user: path" line, then "type bits fingerprint passphrase" line, then "  ok".
    i_priv_clean = next(i for i, ln in enumerate(lines) if ln == "alice: /home/alice/.ssh/id_ed25519_clean")
    assert lines[i_priv_clean + 2] == "  ok"


def test_cli_verbose_flag(keys, tmp_path, monkeypatch, capsys):
    report = _report_with_one_clean_and_one_flagged_key(keys, tmp_path)
    monkeypatch.setattr(audit, "run_audit", lambda *_a, **_k: report)
    audit.main(["--verbose"])
    assert "rsa4096@test" in capsys.readouterr().out
    audit.main([])
    assert "rsa4096@test" not in capsys.readouterr().out
