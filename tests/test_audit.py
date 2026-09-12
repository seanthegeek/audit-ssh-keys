"""Tests for permission checks and the host-key, authorized_keys, and private-key sections.

These generate real keys with ssh-keygen and lay out fake home directories
under tmp_path, then feed fake passwd entries to the audit functions.
"""

from __future__ import annotations

import base64
import io
import json
import os
import pwd
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

import pytest

from audit_ssh_keys import audit
from tests.conftest import (
    RICH_VALID_OPTIONS,
    USER_UID,
    make_user,
    mkdir_clean,
    needs_non_root,
    needs_root,
    needs_ssh_keygen,
    pub,
)

pytestmark = needs_ssh_keygen


def _by_sev(issues: list[audit.Issue]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for i in issues:
        out.setdefault(i.severity, []).append(i.message)
    return out


# A fixed modification time for the tests that assert a date. Local noon, so
# the date it falls on is 2020-02-29 whatever time zone the suite runs in, and
# the tests can assert that literal string instead of recomputing it with the
# helper they are testing.
KNOWN_MTIME = datetime(2020, 2, 29, 12).timestamp()
KNOWN_DATE = "2020-02-29"


def _set_mtime(path: Path, when: float = KNOWN_MTIME) -> Path:
    """Give a file a known modification time."""
    os.utime(path, (when, when))
    return path


# A fixed "now" for the modification-time threshold tests, passed to the audit
# functions so the ages they measure never depend on when the suite runs.
NOW = datetime(2026, 3, 1, 12).timestamp()
DAY = 86400


def _age(path: Path, days: float) -> Path:
    """Backdate a file by a number of days from NOW."""
    return _set_mtime(path, NOW - days * DAY)


def _write_ak(user: pwd.struct_passwd, lines: list[str], mode: int = 0o600, ending: str = "\n") -> Path:
    """Write an authorized_keys file for a fake account, one line per entry.

    The encoding is named rather than left to the locale, so a line holding a
    character outside ASCII lands in the file as the same bytes whatever LANG
    the suite happens to run under. newline="" turns off the one translation
    Python does when it writes text -- turning "\n" into os.linesep -- so the
    endings asked for reach the file as they are written here on any platform.
    On Linux it changes nothing: os.linesep is already "\n", and a "\r" is
    never translated on the way out whatever the setting, so `ending="\r\n"`
    would write CRLF endings without it too.
    """
    ssh_dir = Path(user.pw_dir) / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    ak = ssh_dir / "authorized_keys"
    ak.write_text(ending.join(lines) + ending, encoding="utf-8", newline="")
    ak.chmod(mode)
    return ak


# --- filesystem helpers -------------------------------------------------


def test_stat_if_present_missing_path_is_none(tmp_path: Path):
    assert audit._stat_if_present(tmp_path / "nope") is None


def test_stat_if_present_below_a_regular_file_is_none(tmp_path: Path):
    """A path below a file rather than a directory raises NotADirectoryError, also treated as 'not there'."""
    f = tmp_path / "file"
    f.write_text("x")
    assert audit._stat_if_present(f / "child") is None


@needs_non_root
def test_stat_if_present_raises_on_permission_denied(tmp_path: Path):
    """A directory this account cannot read must raise, not be mistaken for 'not there'.

    This is the regression this helper exists to fix: chmod 0o000 on a
    directory above a path makes os.stat() raise EACCES for everything below
    it, which a naive is_file()/exists() call would either crash on or
    silently swallow depending on the Python version (see the module
    docstring on _stat_if_present).
    """
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    victim = blocked / "child"
    blocked.chmod(0o000)
    try:
        with pytest.raises(PermissionError):
            audit._stat_if_present(victim)
    finally:
        blocked.chmod(0o700)


def test_is_regular_file_true_for_a_file_false_for_a_directory_or_missing_path(tmp_path: Path):
    f = tmp_path / "f"
    f.write_text("x")
    d = tmp_path / "d"
    d.mkdir()
    assert audit._is_regular_file(f) is True
    assert audit._is_regular_file(d) is False
    assert audit._is_regular_file(tmp_path / "missing") is False


def test_last_modified_formats_a_timestamp_as_a_local_date():
    assert audit._last_modified(KNOWN_MTIME) == KNOWN_DATE


def test_last_modified_writes_a_year_below_1000_with_four_digits():
    """The docs promise YYYY-MM-DD, and strftime("%Y") would print year 69 as "69"."""
    assert audit._last_modified(datetime(69, 12, 31, 12).timestamp()) == "0069-12-31"


@pytest.mark.parametrize("mtime", [1e20, -1e20, float("nan"), float("inf")])
def test_last_modified_is_none_for_a_timestamp_out_of_range(mtime: float):
    """A file's modification time is whatever was written to it, so a value the calendar cannot hold must not crash.

    A timestamp far beyond the year the platform can express, one far in the
    past, and the values that are not a time at all each report no date rather
    than aborting the audit part way through.
    """
    assert audit._last_modified(mtime) is None


# --- modification-time thresholds -------------------------------------------


def test_days_uses_the_singular_for_one_day():
    assert audit._days(1) == "1 day"
    assert audit._days(30) == "30 days"


def test_changed_within_and_unchanged_for_split_at_the_window():
    """With the same number of days a file is one or the other, never both and never neither."""
    on_the_boundary = NOW - 7 * DAY
    assert audit._changed_within(on_the_boundary, NOW, 7) is True
    assert audit._unchanged_for(on_the_boundary, NOW, 7) is False

    a_second_older = NOW - 7 * DAY - 1
    assert audit._changed_within(a_second_older, NOW, 7) is False
    assert audit._unchanged_for(a_second_older, NOW, 7) is True


def test_a_modification_time_in_the_future_counts_as_changed_within():
    """A file dated ahead of the clock was certainly written recently, and is not old."""
    tomorrow = NOW + DAY
    assert audit._changed_within(tomorrow, NOW, 7) is True
    assert audit._unchanged_for(tomorrow, NOW, 7) is False


def test_neither_threshold_fires_on_a_modification_time_that_is_not_a_number():
    """stat() never returns nan, but the helpers are plain comparisons, so it compares false rather than raising."""
    nan = float("nan")
    assert audit._changed_within(nan, NOW, 7) is False
    assert audit._unchanged_for(nan, NOW, 7) is False


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
        (0o601, ["LOW"]),
        (0o610, ["LOW"]),
        (0o602, ["LOW"]),
        (0o710, ["LOW"]),
    ],
)
def test_private_key_perms_modes(tmp_path: Path, mode: int, expected: list[str]):
    key = tmp_path / "key"
    key.write_text("x")
    key.chmod(mode)
    issues = audit.check_private_key_perms(key, expected_uid=os.getuid())
    assert [i.severity for i in issues] == expected


@pytest.mark.parametrize("mode", [0o601, 0o610, 0o602])
def test_private_key_perms_unreadable_group_other_bits_message(tmp_path: Path, mode: int):
    """A group/other bit that isn't a read bit gets its own LOW, not the CRITICAL/HIGH read-disclosure message."""
    key = tmp_path / "key"
    key.write_text("x")
    key.chmod(mode)
    issues = audit.check_private_key_perms(key, expected_uid=os.getuid())
    assert len(issues) == 1
    assert issues[0].severity == "LOW"
    assert issues[0].message == f"group/other bits set but not readable by them (mode {mode:04o})"


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


@pytest.mark.parametrize("comment", ["j\u00fcrgen@host", "\ufffd@host"])
def test_fingerprint_line_survives_a_non_ascii_comment_under_an_ascii_locale(
    keys: dict[str, Path], tmp_path: Path, comment: str
):
    """A key comment that the operator's locale cannot encode must not end the audit.

    The line is handed to `ssh-keygen -lf -` as the input of a subprocess. In
    text mode that input is encoded with the locale's codec, and there is no
    way to say what should happen to a character it cannot express, so under
    an ASCII locale a comment holding a
    name spelled in Latin-1 raised UnicodeEncodeError -- and so did a comment
    holding the U+FFFD this tool itself writes in place of a byte that did not
    decode when it read the file. Nothing on that path catches it, so one such
    byte in one unprivileged account's authorized_keys ended the whole root
    audit. Both comments are tried here for that reason.

    The ASCII locale has to be set for the interpreter itself, which only
    happens at start-up, so this runs in a child process: `env -i` with
    `LC_ALL=C`, plus Python's UTF-8 mode and its PEP 538 C locale coercion both
    switched off. That is not an exotic configuration -- coercion has nothing
    to coerce to on a host with no C.UTF-8 locale, which covers glibc before
    2.27 (RHEL and CentOS 7) and the musl images this tool gets copied onto.
    """
    script = tmp_path / "fingerprint_one_line.py"
    script.write_text(
        "import codecs, locale, sys\n"
        "from audit_ssh_keys import audit\n"
        "print(codecs.lookup(locale.getpreferredencoding(False)).name)\n"
        "line = open(sys.argv[1], encoding='utf-8').read().rstrip('\\n')\n"
        "result = audit.fingerprint_line(line)\n"
        "print(result[0] if result is not None else 'no result')\n"
    )
    line_file = tmp_path / "key_line"
    line_file.write_text(f"{pub(keys['ed25519']).rsplit(' ', 1)[0]} {comment}\n", encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(script), str(line_file)],
        # env -i: nothing but the PATH ssh-keygen is found on and the three
        # variables that pin the child's locale.
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(Path(audit.__file__).parents[1]),
            "LC_ALL": "C",
            "PYTHONUTF8": "0",
            "PYTHONCOERCECLOCALE": "0",
        },
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )

    assert proc.returncode == 0, proc.stderr
    # Two words: the child's locale codec, then the key type it read. Anything
    # else -- "no result", say -- should read as a failed assertion here and
    # not as an unpacking error further down.
    assert len(proc.stdout.split()) == 2, proc.stdout
    child_encoding, key_type = proc.stdout.split()
    # Without this the test would pass without ever exercising the bug.
    assert child_encoding == "ascii", f"the child interpreter's locale codec is {child_encoding}, not ASCII"
    assert key_type == "ED25519"


def test_fingerprint_file_pub_and_private_match(keys: dict[str, Path]):
    priv = keys["rsa4096"]
    from_pub = audit.fingerprint_file(priv.with_name(priv.name + ".pub"))
    from_priv = audit.fingerprint_file(priv)
    assert from_pub is not None and from_priv is not None
    assert from_pub[:3] == from_priv[:3] == ("RSA", 4096, from_pub[2])


# The marker every OpenSSH-format private key body starts with.
OPENSSH_MAGIC = b"openssh-key-v1\x00"


def _ssh_string(payload: bytes) -> bytes:
    """One SSH wire-format string: a big-endian 32-bit length, then the bytes."""
    return len(payload).to_bytes(4, "big") + payload


def _openssh_key_file(path: Path, payload: bytes) -> Path:
    """Write a file that looks like an OpenSSH private key but carries an arbitrary body."""
    body = base64.b64encode(OPENSSH_MAGIC + payload).decode()
    path.write_text(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n")
    return path


def _pem_key(path: Path, passphrase: str = "") -> Path:
    """Generate an RSA key in the old PEM format, which has no readable public half."""
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", passphrase, "-f", str(path)],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
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


def _decode_openssh_body(source: Path) -> bytes:
    """Everything after the "openssh-key-v1" marker in a real OpenSSH private key file."""
    lines = [ln.strip() for ln in source.read_text().splitlines() if ln.strip()]
    raw = base64.b64decode("".join(ln for ln in lines[1:] if not ln.startswith("-----")), validate=True)
    assert raw.startswith(OPENSSH_MAGIC)
    return raw[len(OPENSSH_MAGIC) :]


def _write_openssh_key(dest: Path, blob: bytes) -> Path:
    """Write a body back out as an OpenSSH private key file: marker, base64, and both marker lines."""
    body = base64.b64encode(OPENSSH_MAGIC + blob).decode()
    dest.write_text(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n")
    dest.chmod(0o600)
    return dest


def _public_half_bounds(blob: bytes) -> tuple[int, int, int]:
    """Find the key count and the single public half in a decoded key body.

    Returns (offset of the key-count field, start of the public half, end of it).
    """
    offset = 0
    for _ in range(3):  # cipher name, kdf name, kdf options
        _, offset = audit._read_string(blob, offset)
    count_at = offset
    nkeys, public_start = audit._read_uint32(blob, offset)
    assert nkeys == 1
    _, public_end = audit._read_string(blob, public_start)
    return count_at, public_start, public_end


def _truncate_after_public_half(source: Path, dest: Path) -> Path:
    """Copy a real OpenSSH private key, cutting the copy off right after its public half.

    The public half is intact, so the type, size and fingerprint can still be
    read out of it -- but the private half that follows is gone, so ssh and
    sshd cannot load the file at all.
    """
    blob = _decode_openssh_body(source)
    _, _, public_end = _public_half_bounds(blob)
    return _write_openssh_key(dest, blob[:public_end])


def _duplicate_public_half(source: Path, dest: Path) -> Path:
    """Copy a real OpenSSH private key, rewritten to claim two public halves instead of one.

    The second one is just a copy of the first, so every field still parses --
    but ssh only ever loads a file holding exactly one key, so this is not a
    key anyone can use.
    """
    blob = _decode_openssh_body(source)
    count_at, public_start, public_end = _public_half_bounds(blob)
    public_half = blob[public_start:public_end]
    rewritten = blob[:count_at] + (2).to_bytes(4, "big") + public_half + public_half + blob[public_end:]
    return _write_openssh_key(dest, rewritten)


def test_public_key_from_private_is_none_for_a_key_truncated_after_the_public_half(
    keys: dict[str, Path], tmp_path: Path
):
    """A key file cut short after its public half is unusable and must not be reported as healthy.

    `ssh-keygen -lf` prints a fingerprint for such a file, so the check cannot
    lean on ssh-keygen either.
    """
    key = _truncate_after_public_half(keys["ed25519"], tmp_path / "id_ed25519")
    audit.pub_sibling(key).write_text(pub(keys["ed25519"]) + "\n")

    assert audit.public_key_from_private(key) is None
    # A good .pub file beside a broken key says nothing about the key, so no fallback.
    assert audit.fingerprint_private_key(key) == (None, None)
    # The cipher name sits well before the cut, so this answer is still available.
    assert audit.private_key_is_encrypted(key) is False


def test_public_key_from_private_is_none_when_the_end_line_is_missing(keys: dict[str, Path], tmp_path: Path):
    """No `-----END OPENSSH PRIVATE KEY-----` line means the file was cut short."""
    key = tmp_path / "id_ed25519"
    key.write_text(keys["ed25519"].read_text().replace("-----END OPENSSH PRIVATE KEY-----\n", ""))
    key.chmod(0o600)
    audit.pub_sibling(key).write_text(pub(keys["ed25519"]) + "\n")

    assert audit.public_key_from_private(key) is None
    # Still recognised as a corrupt OpenSSH-format key, not as a format whose .pub may stand in.
    assert audit.fingerprint_private_key(key) == (None, None)
    # Without the closing line the base64 body itself may stop mid-line, so nothing
    # decoded from it -- the cipher name included -- can be trusted.
    assert audit.private_key_is_encrypted(key) is None


def test_public_key_from_private_is_none_for_a_file_claiming_two_keys(keys: dict[str, Path], tmp_path: Path):
    """ssh loads a private key file only when it holds exactly one key, so this tool accepts no other count."""
    key = _duplicate_public_half(keys["ed25519"], tmp_path / "id_ed25519")
    audit.pub_sibling(key).write_text(pub(keys["ed25519"]) + "\n")

    assert audit.public_key_from_private(key) is None
    assert audit.fingerprint_private_key(key) == (None, None)


def test_public_key_from_private_is_none_when_bytes_follow_the_private_half(keys: dict[str, Path], tmp_path: Path):
    """ssh refuses a key file with anything after the private half, so this tool must not pass it as healthy."""
    key = _write_openssh_key(tmp_path / "id_ed25519", _decode_openssh_body(keys["ed25519"]) + b"\x00\x00\x00\x00")
    audit.pub_sibling(key).write_text(pub(keys["ed25519"]) + "\n")

    assert audit.public_key_from_private(key) is None
    assert audit.fingerprint_private_key(key) == (None, None)


def _insert_marker_line(source: Path, dest: Path, marker: str) -> Path:
    """Copy a real OpenSSH private key, splicing an extra marker line into the middle of its base64 body."""
    lines = source.read_text().splitlines()
    body_start, body_end = 1, len(lines) - 1  # header is lines[0], footer is lines[-1]
    mid = body_start + (body_end - body_start) // 2
    lines.insert(mid, marker)
    dest.write_text("\n".join(lines) + "\n")
    dest.chmod(0o600)
    return dest


def test_public_key_from_private_is_none_with_a_stray_marker_line_in_the_body(keys: dict[str, Path], tmp_path: Path):
    """A "-----...-----"-shaped line stuck in the middle of the base64 body corrupts it; OpenSSH rejects such a file.

    Stripping every line that starts with "-----" (instead of only the real
    header and footer) would silently drop this line and let the file decode
    as if it were never there -- reporting a corrupt key as healthy. A valid
    `.pub` file sits beside it to prove there is no fallback either.
    """
    key = _insert_marker_line(keys["ed25519"], tmp_path / "id_ed25519", "-----FOO-----")
    audit.pub_sibling(key).write_text(pub(keys["ed25519"]) + "\n")

    assert audit.public_key_from_private(key) is None
    assert audit.fingerprint_private_key(key) == (None, None)


def test_public_key_from_private_is_none_with_a_second_end_marker_in_the_body(keys: dict[str, Path], tmp_path: Path):
    """A second "-----END OPENSSH PRIVATE KEY-----" line stuck mid-body must not be silently dropped either."""
    key = _insert_marker_line(keys["ed25519"], tmp_path / "id_ed25519", audit.OPENSSH_PRIVATE_KEY_FOOTER)
    audit.pub_sibling(key).write_text(pub(keys["ed25519"]) + "\n")

    assert audit.public_key_from_private(key) is None
    assert audit.fingerprint_private_key(key) == (None, None)


def _splice_non_ascii_byte(source: Path, dest: Path) -> Path:
    """Copy a real OpenSSH private key, splicing one 0xFF byte into the middle of its base64 body.

    Nothing else about the file changes. A private key file is ASCII from end
    to end, so OpenSSH rejects this one outright -- but reading it with
    undecodable bytes dropped joins the base64 on either side of the byte back
    together, and the file then decodes exactly as the original did.
    """
    lines = source.read_bytes().split(b"\n")
    body = [i for i, ln in enumerate(lines) if ln and not ln.startswith(b"-----")]
    mid = body[len(body) // 2]
    line = lines[mid]
    cut = len(line) // 2
    lines[mid] = line[:cut] + b"\xff" + line[cut:]
    dest.write_bytes(b"\n".join(lines))
    dest.chmod(0o600)
    return dest


def test_private_key_with_a_non_ascii_byte_in_its_body_is_not_repaired_while_reading(
    keys: dict[str, Path], tmp_path: Path
):
    """One byte that is not ASCII spliced into the base64 body makes a key OpenSSH will not load.

    Reading the file with undecodable bytes dropped silently repaired it: the
    base64 on either side joined up, the body decoded cleanly, and a file ssh
    refuses to load was reported as a healthy key. A valid `.pub` file sits
    beside it to prove there is no fallback to that either.
    """
    key = _splice_non_ascii_byte(keys["ed25519"], tmp_path / "id_ed25519")
    audit.pub_sibling(key).write_text(pub(keys["ed25519"]) + "\n")

    assert audit.public_key_from_private(key) is None
    assert audit.fingerprint_private_key(key) == (None, None)
    assert audit.private_key_is_encrypted(key) is None


def _splice_non_ascii_byte_into_the_header(source: Path, dest: Path) -> Path:
    """Copy a real OpenSSH private key with one 0xFF byte stuck on the end of its header line."""
    raw = source.read_bytes()
    header = audit.OPENSSH_PRIVATE_KEY_HEADER.encode("ascii")
    assert raw.startswith(header)
    dest.write_bytes(header + b"\xff" + raw[len(header) :])
    dest.chmod(0o600)
    return dest


def test_private_key_with_a_mangled_header_line_is_not_reported_as_an_unrelated_pub(
    keys: dict[str, Path], tmp_path: Path
):
    """A stray byte on the header line must not send the file down the legacy `.pub` fallback.

    The file is still an attempt at the current OpenSSH format, so it counts as
    one -- and nothing in it can be trusted, so it is reported as
    unfingerprintable rather than handed to the fallback meant for the older
    PEM/PKCS#8 formats, which would answer with whatever unrelated key happens
    to be sitting in the `.pub` file beside it. Comparing the header line as
    decoded text (with undecodable bytes replaced) made one stray byte in it
    answer "not this format", which is the exact hole this check closes.
    """
    key = _splice_non_ascii_byte_into_the_header(keys["ed25519"], tmp_path / "id_ed25519")
    audit.pub_sibling(key).write_text(pub(keys["rsa2048"]) + "\n")  # a valid, but unrelated, key

    assert audit.looks_like_private_key(key) is True  # so the file is audited at all
    assert audit._private_key_format(key) == "openssh"
    # The full format is not met: the header line is not the header, and a
    # private key file holding a byte that is not ASCII is corrupt either way.
    assert audit.public_key_from_private(key) is None
    assert audit.fingerprint_private_key(key) == (None, None)
    assert audit.private_key_is_encrypted(key) is None


def test_empty_or_unrecognised_key_file_is_not_reported_as_the_pub_beside_it(keys: dict[str, Path], tmp_path: Path):
    """A readable file that holds no private-key header must not borrow the answer from a `.pub` file.

    The `.pub` fallback exists for the old PEM and PKCS#8 formats, which carry
    no public half inside them, so the `.pub` file beside one of those is the
    only thing left to read. A zero-byte file is not one of those formats, and
    neither is a file holding arbitrary text. Answering from the `.pub` file put
    a healthy-looking Ed25519 host key in the report for a zero-byte
    `ssh_host_ed25519_key` that `sshd` can load nothing at all from.
    """
    empty = tmp_path / "ssh_host_ed25519_key"
    empty.write_bytes(b"")
    empty.chmod(0o600)
    audit.pub_sibling(empty).write_text(pub(keys["ed25519"]) + "\n")
    assert audit.fingerprint_private_key(empty) == (None, None)
    assert audit._private_key_format(empty) is None

    # The same file as the audit meets it: reported as unfingerprintable, not as
    # the key in the `.pub` file.
    findings = audit.audit_host_keys({"hostkey": [str(empty)]}, min_rsa_bits=3072, owner_uid=os.getuid())
    assert [(f.path, f.key_type, f.fingerprint) for f in findings if f.path == str(empty)] == [(str(empty), "?", "")]
    assert "could not fingerprint host key" in [i.message for f in findings for i in f.issues]

    garbage = tmp_path / "id_garbage"
    garbage.write_text("this is not a key at all\nnor is this line\n")
    garbage.chmod(0o600)
    audit.pub_sibling(garbage).write_text(pub(keys["ed25519"]) + "\n")
    assert audit.fingerprint_private_key(garbage) == (None, None)
    assert audit._private_key_format(garbage) is None


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


def test_fingerprint_private_key_pem_prefers_the_private_key_over_a_stale_pub(keys: dict[str, Path], tmp_path: Path):
    """A stale .pub beside an unencrypted PEM key must not win: the private key itself is read first.

    Regression test for a Copilot review finding: `ssh-keygen -lf` silently
    prefers a `<path>.pub` sibling over the private key file itself, so
    fingerprinting the private key in place -- as opposed to through the
    symlink trick in `_fingerprint_private_file_alone`, which hides the .pub
    from ssh-keygen -- would just echo the stale .pub instead of catching it.
    Before the fix, this scenario silently graded the wrong key.
    """
    plain = _pem_key(tmp_path / "plain")
    # Capture the PEM key's own fingerprint before overwriting its real .pub.
    expected = audit.fingerprint_file(audit.pub_sibling(plain))
    assert expected is not None
    audit.pub_sibling(plain).write_text(pub(keys["ed25519"]) + "\n")

    result, mismatch = audit.fingerprint_private_key(plain)
    assert result is not None and result[:3] == ("RSA", 2048, expected[2])
    assert mismatch is not None and mismatch.severity == "LOW"
    assert mismatch.message.startswith(f"{plain.name}.pub does not match this private key")
    assert "ED25519" in mismatch.message


def test_fingerprint_private_key_encrypted_pem_with_stale_pub_cannot_be_detected(keys: dict[str, Path], tmp_path: Path):
    """Documents a real limitation: when the private key can't be read at all, a stale .pub goes undetected.

    A passphrase-protected PEM key has no readable embedded public half, and
    ssh-keygen cannot fingerprint the encrypted file without the passphrase,
    so the .pub file is the only thing left to report -- even when it
    belongs to a different key entirely. There is nothing to compare it
    against, so no mismatch can be raised.
    """
    encrypted = _pem_key(tmp_path / "encrypted_pem", passphrase="hunter2")
    audit.pub_sibling(encrypted).write_text(pub(keys["ed25519"]) + "\n")

    result, mismatch = audit.fingerprint_private_key(encrypted)
    assert result is not None and result[0] == "ED25519"
    assert mismatch is None


def test_fingerprint_private_key_world_readable_pem_falls_back_to_its_own_pub(tmp_path: Path):
    """ssh-keygen refuses to open a private key file that its owner has made group/other readable.

    The key files this test writes are owned by the uid running the test
    suite, and ssh-keygen refuses to load a key it owns once group or other
    bits are set on it -- so this is deterministic whether the suite runs as
    root or not. With the private file unreadable to ssh-keygen, its own
    matching .pub is the only thing left to report from.
    """
    plain = _pem_key(tmp_path / "plain")
    plain.chmod(0o644)
    assert audit._fingerprint_private_file_alone(plain) is None  # confirms ssh-keygen actually refused it

    result, mismatch = audit.fingerprint_private_key(plain)
    assert result is not None and result[:2] == ("RSA", 2048)
    assert mismatch is None


def test_fingerprint_private_file_alone_returns_none_when_the_symlink_cannot_be_created(
    keys: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A symlink that cannot be created leaves the .pub file as the only thing left to read."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise OSError("no symlinks here")

    plain = _pem_key(tmp_path / "plain")
    audit.pub_sibling(plain).write_text(pub(keys["ed25519"]) + "\n")
    monkeypatch.setattr(Path, "symlink_to", refuse)

    assert audit._fingerprint_private_file_alone(plain) is None
    result, mismatch = audit.fingerprint_private_key(plain)
    # The unrelated .pub, which is all that is left once the private key cannot be reached.
    assert result is not None and result[0] == "ED25519"
    assert mismatch is None


def test_fingerprint_private_file_alone_does_not_hide_a_missing_ssh_keygen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A host with no ssh-keygen must not look like a key that needs a passphrase.

    FileNotFoundError is an OSError, so running the ssh-keygen call inside the
    same try as the temporary directory and the symlink would turn "ssh-keygen
    is not installed" into a silent fall back to whatever .pub file sits
    beside the key.
    """
    plain = _pem_key(tmp_path / "plain")

    def missing(path: Path) -> tuple[str, int, str, str] | None:
        raise FileNotFoundError(2, "No such file or directory", "ssh-keygen")

    monkeypatch.setattr(audit, "fingerprint_file", missing)

    with pytest.raises(FileNotFoundError):
        audit._fingerprint_private_file_alone(plain)


def test_fingerprint_private_key_falls_back_when_the_pub_sibling_is_unparsable(tmp_path: Path):
    """A PEM key is fingerprinted from the private file itself even when a garbage .pub sits beside it.

    For PEM/PKCS#8 keys, the private key file is tried first -- not as a
    fallback that only kicks in once the .pub turns out to be unparsable.
    A garbage (not merely stale) .pub beside the key therefore changes
    nothing about how the private key itself gets read.
    """
    plain = _pem_key(tmp_path / "plain")
    audit.pub_sibling(plain).write_text("not a key\n")
    result, mismatch = audit.fingerprint_private_key(plain)
    assert result is not None and result[:2] == ("RSA", 2048)
    assert mismatch is None


def test_fingerprint_private_key_pem_with_its_own_matching_pub_is_fingerprinted_via_it(tmp_path: Path):
    """A legacy PEM key with its real, matching .pub still in place is read from that .pub.

    This only happens here because the key is passphrase-protected: with no
    passphrase supplied, ssh-keygen cannot open the private file directly, so
    the .pub file is the only thing left to read. An unencrypted PEM key is
    fingerprinted from the private file itself instead -- see
    test_fingerprint_private_key_pem_prefers_the_private_key_over_a_stale_pub.
    """
    encrypted = _pem_key(tmp_path / "encrypted_pem", passphrase="hunter2")
    result, mismatch = audit.fingerprint_private_key(encrypted)
    assert result is not None and result[:2] == ("RSA", 2048)
    assert mismatch is None


def test_fingerprint_private_key_corrupt_openssh_body_is_not_reported_as_an_unrelated_pub(
    keys: dict[str, Path], tmp_path: Path
):
    """A corrupt OpenSSH-format key must not be reported as whatever .pub file happens to sit next to it.

    The .pub fallback exists for legacy PEM/PKCS#8 keys, which have no
    readable public half at all. A truncated *current*-format key also has no
    readable public half, but it is corrupt, not merely an old format -- so
    grading it as the key described by a neighbouring .pub (which could
    belong to any other key) would misattribute it.
    """
    # Same truncated body as the "truncated" case in test_public_key_from_private_is_none_for_corrupt_bodies.
    payload = (
        _ssh_string(b"none")
        + _ssh_string(b"none")
        + _ssh_string(b"")
        + (1).to_bytes(4, "big")
        + (99).to_bytes(4, "big")
    )
    key = _openssh_key_file(tmp_path / "id_ed25519", payload)
    audit.pub_sibling(key).write_text(pub(keys["rsa2048"]) + "\n")  # a valid, but unrelated, key
    key.chmod(0o600)

    assert audit.fingerprint_private_key(key) == (None, None)


def _corrupt_the_public_half(source: Path, dest: Path) -> Path:
    """Copy a real OpenSSH private key, replacing its public half with a type name and then garbage.

    Every field in the file still parses -- the type name reads as
    `ssh-ed25519`, and the private half is left exactly as it was -- so the
    file passes every whole-file check. What it does not hold is a public key
    ssh-keygen can fingerprint.
    """
    blob = _decode_openssh_body(source)
    _, public_start, public_end = _public_half_bounds(blob)
    corrupt = _ssh_string(b"ssh-ed25519") + b"garbage"
    return _write_openssh_key(dest, blob[:public_start] + _ssh_string(corrupt) + blob[public_end:])


def test_fingerprint_private_key_is_none_when_the_embedded_public_half_cannot_be_fingerprinted(
    keys: dict[str, Path], tmp_path: Path
):
    """A current-format key whose public half reads but cannot be fingerprinted is corrupt, `.pub` or no `.pub`.

    public_key_from_private takes only the type name out of the embedded
    public blob, so a blob whose remaining bytes are garbage still yields a
    "<type> <base64>" line -- one ssh-keygen then refuses. Before the fix that
    sent the key down the path meant for legacy PEM keys, and it was reported
    as whatever `.pub` file happened to sit beside it.
    """
    key = _corrupt_the_public_half(keys["ed25519"], tmp_path / "id_ed25519")
    audit.pub_sibling(key).write_text(pub(keys["ed25519"]) + "\n")

    line = audit.public_key_from_private(key)
    assert line is not None and line.startswith("ssh-ed25519 ")  # the type name still reads
    assert audit.fingerprint_line(line) is None  # but the blob is not a key
    assert audit.fingerprint_private_key(key) == (None, None)


def _corrupt_the_private_half(source: Path, dest: Path) -> Path:
    """Copy a real OpenSSH private key with the first byte of its private half flipped.

    That byte belongs to the first of the two check integers ssh compares when
    it loads a key, and the private half keeps the exact length it had, so
    every field in the file still parses and the public half still reads
    perfectly. Only ssh's own loader can tell this file from a good one.
    """
    blob = _decode_openssh_body(source)
    _, _, public_end = _public_half_bounds(blob)
    private, end = audit._read_string(blob, public_end)
    assert end == len(blob)
    flipped = bytes([private[0] ^ 0xFF]) + private[1:]
    return _write_openssh_key(dest, blob[:public_end] + _ssh_string(flipped))


def test_fingerprint_private_key_is_none_when_ssh_cannot_load_the_private_half(keys: dict[str, Path], tmp_path: Path):
    """A key whose private half ssh cannot load is not a usable key, however well its public half reads.

    ssh builds the key it actually uses out of the private half, so a file
    whose private half ssh refuses to load authenticates nobody. The clean case --
    an intact unencrypted key at mode 0600, still fingerprinted and still
    reporting no problem -- is covered by test_private_keys_end_to_end, which
    audits exactly such a key.
    """
    key = _corrupt_the_private_half(keys["ed25519"], tmp_path / "id_ed25519")
    audit.pub_sibling(key).write_text(pub(keys["ed25519"]) + "\n")

    # The whole point of this corruption: the public half is untouched and reads as it always did.
    assert audit.public_key_from_private(key) == audit.public_key_from_private(keys["ed25519"])
    # `ssh-keygen -l` cannot see the problem: handed a private key file in this
    # format it answers from the public half inside it, writing the private
    # half's failure to its debug log only. That is why the check below asks
    # ssh-keygen for the public key derived from the private half instead.
    assert audit._fingerprint_private_file_alone(key) is not None
    assert audit._ssh_keygen_would_refuse(key) is False  # mode 0600, so the check really does run
    assert audit._ssh_can_load_private_key(key) is False
    assert audit.fingerprint_private_key(key) == (None, None)


def test_fingerprint_private_key_cannot_check_the_private_half_of_an_encrypted_key(
    keys: dict[str, Path], tmp_path: Path
):
    """Documents a limitation: the private half of a passphrase-protected key cannot be checked at all.

    Loading it needs the passphrase, which this tool never has, so the very
    corruption caught above goes undetected here and the key is still reported
    from its public half.
    """
    key = _corrupt_the_private_half(keys["encrypted"], tmp_path / "id_ed25519")
    audit.pub_sibling(key).write_bytes(keys["encrypted"].with_name("encrypted.pub").read_bytes())

    result, mismatch = audit.fingerprint_private_key(key)
    assert result is not None and result[0] == "ED25519"
    assert mismatch is None


@needs_non_root
def test_fingerprint_private_key_cannot_check_the_private_half_of_a_key_ssh_keygen_refuses(
    keys: dict[str, Path], tmp_path: Path
):
    """Documents a limitation: ssh-keygen will not open a key the running account owns and others can see.

    There is no way to ask ssh to load such a file, so corruption inside its
    private half goes undetected and the key is still reported from its public
    half. The same file at mode 0600 is read fine, which is what the first
    assertion pins down.
    """
    key = _corrupt_the_private_half(keys["ed25519"], tmp_path / "id_ed25519")
    assert audit._ssh_keygen_would_refuse(key) is False  # as written: mode 0600
    key.chmod(0o644)
    assert audit._ssh_keygen_would_refuse(key) is True

    result, mismatch = audit.fingerprint_private_key(key)
    assert result is not None and result[0] == "ED25519"
    assert mismatch is None


def test_ssh_keygen_would_refuse_a_file_it_cannot_stat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A file that cannot be stat'd must be assumed unreadable by ssh-keygen, not assumed fine.

    Answering False would send the caller on to run ssh-keygen over the key and
    read the refusal as "ssh cannot load this key", turning a problem with the
    file's permissions into a wrong answer about the key itself.
    """
    key = tmp_path / "id_ed25519"
    key.write_text(audit.OPENSSH_PRIVATE_KEY_HEADER + "\n")
    key.chmod(0o600)
    assert audit._ssh_keygen_would_refuse(key) is False  # nothing wrong with it as written

    def raise_oserror(*args: object, **kwargs: object) -> os.stat_result:
        raise OSError("cannot stat this")

    monkeypatch.setattr(Path, "stat", raise_oserror)
    assert audit._ssh_keygen_would_refuse(key) is True


def test_fingerprint_private_key_survives_a_comment_that_is_not_utf8(tmp_path: Path):
    """A key whose embedded comment is not valid UTF-8 must not take the whole audit down.

    `ssh-keygen -y` prints the key's comment exactly as the bytes sit in the
    file (unlike `ssh-keygen -l`, which escapes them), so collecting its output
    as decoded text raised UnicodeDecodeError out of subprocess.run and aborted
    the run. Only the exit status is wanted, so the output is never decoded.
    """
    key = tmp_path / "id_ed25519"
    subprocess.run(
        # Latin-1 bytes straight into the comment, which ssh-keygen stores as given.
        [b"ssh-keygen", b"-q", b"-t", b"ed25519", b"-N", b"", b"-C", b"M\xfcller", b"-f", os.fsencode(key)],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    assert b"M\xfcller" in audit.pub_sibling(key).read_bytes()  # the comment really is not UTF-8
    assert audit._ssh_keygen_would_refuse(key) is False  # mode 0600, so the private-half check runs
    assert audit._ssh_can_load_private_key(key) is True

    result, mismatch = audit.fingerprint_private_key(key)
    assert result is not None and result[0] == "ED25519"
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


@needs_non_root
def test_private_key_format_is_none_for_a_file_that_cannot_be_read(tmp_path: Path):
    """An unreadable file answers "cannot tell", never "one of the older formats", and must not raise.

    The difference matters to the caller: only a "legacy" answer sends a file
    down the fallback meant for the older PEM formats, which reports whatever
    `.pub` file sits beside it.
    """
    key = tmp_path / "id_ed25519"
    key.write_text(audit.OPENSSH_PRIVATE_KEY_HEADER + "\n")
    assert audit._private_key_format(key) == "openssh"  # readable as written
    key.chmod(0o000)
    try:
        assert audit._private_key_format(key) is None
    finally:
        key.chmod(0o600)


@needs_non_root
def test_unreadable_key_is_not_reported_as_the_pub_file_beside_it(keys: dict[str, Path], tmp_path: Path):
    """A key file this tool cannot read must not be reported as whatever `.pub` file sits next to it.

    This is what a non-root run of the audit meets on a root-owned host key:
    the file cannot be read, so nothing about the key is known, and the `.pub`
    file beside it could describe any other key -- here it deliberately holds
    one. Answering from it would put a fingerprint in the report that the
    operator has no reason to doubt and that belongs to a different key
    entirely.
    """
    key = tmp_path / "ssh_host_ed25519_key"
    key.write_bytes(keys["ed25519"].read_bytes())
    audit.pub_sibling(key).write_text(pub(keys["rsa2048"]) + "\n")  # a valid, but unrelated, key
    key.chmod(0o000)
    try:
        assert audit.fingerprint_private_key(key) == (None, None)

        findings = audit.audit_host_keys({"hostkey": [str(key)]}, min_rsa_bits=3072, owner_uid=os.getuid())
        # Mode 0000 on a file this account owns is clean as far as sshd is
        # concerned, and whether a passphrase is set cannot be told from a file
        # that cannot be read, so this one finding is the whole report -- no
        # Ed25519 note either, because the key set is unknown, not known to be
        # missing an Ed25519 key.
        assert [(f.path, f.key_type, f.fingerprint) for f in findings] == [(str(key), "?", "")]
        assert [(i.severity, i.message) for i in findings[0].issues] == [("LOW", "could not fingerprint host key")]
    finally:
        key.chmod(0o600)


@needs_non_root
def test_no_ed25519_note_when_a_host_key_could_not_be_fingerprinted(keys: dict[str, Path], tmp_path: Path):
    """An unreadable host key leaves the set of key types unknown, so the Ed25519 note must stay quiet.

    This is what a non-root run of the audit meets: the RSA key reads fine, the
    Ed25519 key cannot be read at all, so its type is never recorded as present.
    Adding the note from that would tell the operator to run `ssh-keygen -A` on
    a host that already has an Ed25519 host key.
    """
    rsa = tmp_path / "ssh_host_rsa_key"
    rsa.write_bytes(keys["rsa4096"].read_bytes())
    rsa.chmod(0o600)
    unreadable = tmp_path / "ssh_host_ed25519_key"
    unreadable.write_bytes(keys["ed25519"].read_bytes())
    unreadable.chmod(0o000)
    try:
        findings = audit.audit_host_keys(
            {"hostkey": [str(rsa), str(unreadable)]}, min_rsa_bits=3072, owner_uid=os.getuid()
        )
    finally:
        unreadable.chmod(0o600)

    assert [f.path for f in findings] == [str(rsa), str(unreadable)]
    assert not any("Ed25519" in i.message for f in findings for i in f.issues)
    assert [i.message for i in findings[1].issues] == ["could not fingerprint host key"]


# --- audit_host_keys ----------------------------------------------------------


def test_an_oversized_private_host_key_file_is_reported_as_one_that_could_not_be_fingerprinted(
    keys: dict[str, Path], tmp_path: Path
):
    """A host key file holding a private key, over this tool's own size limit, is not read past it.

    The limit is on reading a private key file into memory, and it is this
    tool's, not ssh's: sshd loads a host key file of this size perfectly well
    (see MAX_PRIVATE_KEY_FILE_SIZE), so the finding says that the audit could
    not fingerprint the key and nothing about what sshd can do with it. As
    with any file whose format could not be established, the `.pub` file
    beside it gets no say -- here it deliberately holds a different key --
    because nothing says that file describes this one.

    A HostKey naming an oversized *public* key file is the test below, and it
    is not treated this way at all.
    """
    key = tmp_path / "ssh_host_ed25519_key"
    key.write_bytes(keys["ed25519"].read_bytes().ljust(audit.MAX_PRIVATE_KEY_FILE_SIZE + 1, b"\n"))
    key.chmod(0o600)
    audit.pub_sibling(key).write_text(pub(keys["rsa2048"]) + "\n")  # a valid, but unrelated, key

    findings = audit.audit_host_keys({"hostkey": [str(key)]}, min_rsa_bits=3072, owner_uid=os.getuid())

    assert [(f.path, f.key_type, f.fingerprint) for f in findings] == [(str(key), "?", "")]
    assert [(i.severity, i.message) for i in findings[0].issues] == [("LOW", "could not fingerprint host key")]


def test_an_oversized_public_host_key_file_is_still_fingerprinted(keys: dict[str, Path], tmp_path: Path):
    """The 1 MiB limit is on reading a private key file, so it does not reach a public one.

    A HostKey that names a public key file is handed straight to `ssh-keygen`,
    which reads the file itself -- there is no bounded read in this tool to
    apply a limit to, and adding one would turn down a file `ssh-keygen`
    fingerprints without complaint. With a HostKeyAgent set that is a working
    arrangement, so the key is fingerprinted and graded like any other, at any
    size. That is what docs/how-it-works.md and the `could not fingerprint
    host key` row of docs/findings.md now say; both used to say that any host
    key file over 1 MiB went unfingerprinted, which was never true of this
    shape.
    """
    hk = tmp_path / "ssh_host_ed25519_key.pub"
    # Padded past the limit with the blank lines ssh-keygen ignores, so the
    # file is over the limit while still holding exactly one readable key.
    hk.write_bytes((pub(keys["ed25519"]) + "\n").encode().ljust(audit.MAX_PRIVATE_KEY_FILE_SIZE + 1, b"\n"))
    assert hk.stat().st_size > audit.MAX_PRIVATE_KEY_FILE_SIZE

    config = {"hostkey": [str(hk)], "hostkeyagent": ["/run/host-key-agent.sock"]}
    findings = audit.audit_host_keys(config, min_rsa_bits=3072, owner_uid=os.getuid())

    finding = next(f for f in findings if f.path == str(hk))
    assert (finding.key_type, finding.bits) == ("ED25519", 256)
    assert finding.fingerprint
    assert [(i.severity, i.message) for i in finding.issues] == [
        ("INFO", "public key file; the private half is held by HostKeyAgent and cannot be audited here")
    ]
    # Graded, so the host counts as having an Ed25519 key: no "no Ed25519 host
    # key present" finding is added for it.
    assert not any(f.path == "(none)" for f in findings)


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
    # A missing configured HostKey gets its own per-file finding, never the
    # "no default host key" aggregate -- that one only applies when nothing
    # was configured at all.
    assert not any("no host key exists at any default path" in i.message for f in findings for i in f.issues)


def test_host_key_naming_a_public_key_file_with_an_agent_is_info(keys: dict[str, Path], tmp_path: Path):
    """With HostKeyAgent set, a public-key HostKey is how sshd is told which agent key to serve.

    sshd tries sshkey_load_private() on every HostKey, falls back to
    sshkey_load_public(), and with an agent configured logs "will rely on agent
    for hostkey" and serves that key (sshd.c). The private half is not on disk,
    so there are no permissions, no passphrase and no `.pub` sibling to check --
    not even at mode 0644, which on a private key file would be a CRITICAL, and
    not even when a `.pub` file for a different key does sit next to it.
    """
    hk = tmp_path / "ssh_host_ed25519_key.pub"
    hk.write_text(pub(keys["ed25519"]) + "\n")
    hk.chmod(0o644)
    # A `.pub` sibling holding a different key entirely. On a private key file
    # this is a LOW "does not match this private key"; here there is no private
    # key to compare it against, so the check must not run at all.
    hk.with_name(hk.name + ".pub").write_text(pub(keys["rsa4096"]) + "\n")

    config = {"hostkey": [str(hk)], "hostkeyagent": ["/run/host-key-agent.sock"]}
    findings = audit.audit_host_keys(config, min_rsa_bits=3072, owner_uid=os.getuid())

    finding = next(f for f in findings if f.path == str(hk))
    assert (finding.key_type, finding.bits) == ("ED25519", 256)
    assert finding.fingerprint
    assert [(i.severity, i.message) for i in finding.issues] == [
        ("INFO", "public key file; the private half is held by HostKeyAgent and cannot be audited here")
    ]
    assert not any("does not match" in i.message for i in finding.issues)
    # sshd serves this key through the agent, so it counts as the host's Ed25519 key.
    assert not any(f.path == "(none)" for f in findings)


def test_host_key_held_by_an_agent_is_still_graded(keys: dict[str, Path], tmp_path: Path):
    """An agent-held key is still a key sshd serves, so its algorithm and size are graded."""
    hk = tmp_path / "ssh_host_rsa_key.pub"
    hk.write_text(pub(keys["rsa1024"]) + "\n")

    config = {"hostkey": [str(hk)], "hostkeyagent": ["/run/host-key-agent.sock"]}
    findings = audit.audit_host_keys(config, min_rsa_bits=3072, owner_uid=os.getuid())

    finding = next(f for f in findings if f.path == str(hk))
    assert any("below 2048" in m for m in _by_sev(finding.issues)["CRITICAL"])


@pytest.mark.parametrize(
    "config_extra",
    [
        pytest.param({}, id="HostKeyAgent absent"),
        pytest.param({"hostkeyagent": ["none"]}, id="HostKeyAgent none"),
        pytest.param({"hostkeyagent": ["None"]}, id="HostKeyAgent None, any case"),
    ],
)
def test_host_key_naming_a_public_key_file_without_an_agent_is_low(
    keys: dict[str, Path], tmp_path: Path, config_extra: dict[str, list[str]]
):
    """Without an agent a public-key HostKey is unusable, and it is not a private key file either.

    Verified against OpenSSH 10.2: `sshd -t` with such a HostKey prints
    "Unable to load host key: <path>" and, with no other key configured,
    "no hostkeys available -- exiting". So the permission and passphrase
    checks -- which are about private key files -- must not run on it, and the
    key's type must not count as a type the host can offer.
    """
    hk = tmp_path / "ssh_host_ed25519_key.pub"
    hk.write_text(pub(keys["ed25519"]) + "\n")
    hk.chmod(0o644)

    config = {"hostkey": [str(hk)], **config_extra}
    findings = audit.audit_host_keys(config, min_rsa_bits=3072, owner_uid=os.getuid())

    finding = next(f for f in findings if f.path == str(hk))
    assert (finding.key_type, finding.bits) == ("ED25519", 256)
    assert finding.fingerprint
    assert [(i.severity, i.message) for i in finding.issues] == [
        (
            "LOW",
            "HostKey names a public key file and no HostKeyAgent is set; sshd cannot load a private key from it",
        )
    ]
    # sshd has no usable Ed25519 key from this line, so the Ed25519 note still fires.
    assert any(f.path == "(none)" and "Ed25519" in f.issues[0].message for f in findings)


def test_host_key_naming_a_public_key_file_without_an_agent_is_not_graded(keys: dict[str, Path], tmp_path: Path):
    """sshd can never use the key, so grading its size would imply the host offers something it does not.

    An RSA-1024 private host key is a CRITICAL. Named as a public file with no
    agent, it is only the LOW saying sshd cannot load a private key from it:
    there is nothing for an attacker to reach, because sshd never serves it.
    """
    hk = tmp_path / "ssh_host_rsa_key.pub"
    hk.write_text(pub(keys["rsa1024"]) + "\n")

    findings = audit.audit_host_keys({"hostkey": [str(hk)]}, min_rsa_bits=3072, owner_uid=os.getuid())

    finding = next(f for f in findings if f.path == str(hk))
    assert (finding.key_type, finding.bits) == ("RSA", 1024)
    assert [(i.severity, i.message) for i in finding.issues] == [
        (
            "LOW",
            "HostKey names a public key file and no HostKeyAgent is set; sshd cannot load a private key from it",
        )
    ]


def _ed25519_host_certificate(tmp_path: Path, name: str) -> Path:
    """Sign a fresh ed25519 host key with a fresh CA and return the certificate file's path."""

    def keygen(path: Path, *extra: str) -> None:
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path), *extra],
            check=True,
            capture_output=True,
            stdin=subprocess.DEVNULL,
        )

    ca = tmp_path / f"{name}-ca"
    host_key = tmp_path / name
    keygen(ca)
    keygen(host_key)
    subprocess.run(
        ["ssh-keygen", "-q", "-s", str(ca), "-I", "test", "-h", str(host_key) + ".pub"],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    return host_key.with_name(host_key.name + "-cert.pub")


@pytest.mark.parametrize(
    "config_extra",
    [
        pytest.param({}, id="no HostKeyAgent"),
        pytest.param({"hostkeyagent": ["/run/host-key-agent.sock"]}, id="HostKeyAgent set"),
    ],
)
def test_host_key_naming_a_certificate_file_is_low(tmp_path: Path, config_extra: dict[str, list[str]]):
    """A certificate is not a host key sshd can load, with or without an agent.

    The "will rely on agent for hostkey" fallback in sshd.c is only taken for a
    plain key type, so a certificate named by HostKey is unusable either way.
    Verified against OpenSSH 10.2 with a live agent holding both the key and
    its certificate: `sshd -t` still logs "Unable to load host key" for the
    certificate file and exits with "no hostkeys available", while the same
    setup with the plain `.pub` file loads the key through the agent. So the
    key's type must not count as one the host can offer, and grading its
    algorithm and size would wrongly imply it does something.
    """
    cert = _ed25519_host_certificate(tmp_path, "ssh_host_ed25519_key")

    config = {"hostkey": [str(cert)], **config_extra}
    findings = audit.audit_host_keys(config, min_rsa_bits=3072, owner_uid=os.getuid())

    finding = next(f for f in findings if f.path == str(cert))
    assert finding.key_type == "ED25519-CERT"
    assert [(i.severity, i.message) for i in finding.issues] == [
        (
            "LOW",
            "HostKey names a certificate file; sshd cannot load a host key from it "
            "(a certificate belongs on a HostCertificate line)",
        )
    ]
    # The Ed25519 inside the certificate is not a host key sshd can serve, so
    # the "no Ed25519 host key present" note still fires.
    assert any(f.path == "(none)" and "Ed25519" in f.issues[0].message for f in findings)


def test_server_config_warns_when_a_host_key_agent_is_set():
    """Keys an agent holds are not on disk, so the report has to say they were not audited."""
    _, coverage = audit.audit_server_config({"hostkeyagent": ["/run/agent.sock"]}, "sshd -T", "")
    assert (
        "HostKeyAgent is set (/run/agent.sock); private host keys held by the agent "
        "are not on disk and cannot be audited." in coverage
    )


@pytest.mark.parametrize(
    "config",
    [pytest.param({}, id="absent"), pytest.param({"hostkeyagent": ["none"]}, id="none")],
)
def test_server_config_says_nothing_about_an_unset_host_key_agent(config: dict[str, list[str]]):
    _, coverage = audit.audit_server_config(config, "sshd -T", "")
    assert not any("HostKeyAgent" in c for c in coverage)


def test_host_key_group_accessible_and_root_owned_is_refused_by_sshd(keys: dict[str, Path], tmp_path: Path):
    """sshkey_perm_ok() refuses a key over its mode only when the account running sshd owns it.

    Here the expected owner does own the file, which is the production case of a
    root-owned host key read by a root sshd, so sshd turns it down.
    """
    ed = tmp_path / "ssh_host_ed25519_key"
    ed.write_bytes(keys["ed25519"].read_bytes())
    ed.chmod(0o640)

    findings = audit.audit_host_keys({"hostkey": [str(ed)]}, min_rsa_bits=3072, owner_uid=os.getuid())

    finding = next(f for f in findings if f.path == str(ed))
    assert _by_sev(finding.issues)["HIGH"] == ["group-accessible private key (mode 0640); sshd refuses to load it"]


def test_host_key_not_owned_by_root_is_loaded_anyway(keys: dict[str, Path], tmp_path: Path):
    """A host key somebody else owns is loaded whatever its mode, so the message must not claim otherwise.

    sshkey_perm_ok() only looks at the mode when the file belongs to the uid
    running the program; sshd runs as root, so another account's host key is
    read regardless -- and that account, plus anyone its mode admits, can read
    and replace the server's identity key.
    """
    if os.getuid() == 0:
        pytest.skip("running as root: the file IS root-owned, so there is no mismatch to observe")
    ed = tmp_path / "ssh_host_ed25519_key"
    ed.write_bytes(keys["ed25519"].read_bytes())
    ed.chmod(0o640)

    findings = audit.audit_host_keys({"hostkey": [str(ed)]}, min_rsa_bits=3072)  # owner_uid defaults to root

    finding = next(f for f in findings if f.path == str(ed))
    assert _by_sev(finding.issues)["HIGH"] == [
        f"owned by {audit.uid_name(os.getuid())}, expected root",
        "group-accessible private key (mode 0640); sshd still loads it because root does not own it",
    ]


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


def test_host_key_that_cannot_be_fingerprinted_still_gets_perms_and_passphrase_checked(tmp_path: Path):
    """A host key ssh-keygen can't read at all must still get its permission and passphrase checks.

    An encrypted, legacy-PEM host key with no .pub sibling cannot be
    fingerprinted by any of the tool's methods (ssh-keygen refuses to read an
    encrypted key without its passphrase, whatever the file's mode -- see the
    mode-0600 case below). That must not skip the checks that do not depend
    on fingerprinting: file permissions and whether a passphrase is set.
    """
    host_key = tmp_path / "ssh_host_rsa_key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", "somepass", "-f", str(host_key)],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    audit.pub_sibling(host_key).unlink()  # no .pub: nothing to fall back to
    host_key.chmod(0o644)

    findings = audit.audit_host_keys({"hostkey": [str(host_key)]}, min_rsa_bits=3072, owner_uid=os.getuid())
    finding = next(f for f in findings if f.path == str(host_key))
    assert (finding.key_type, finding.bits, finding.fingerprint) == ("?", 0, "")
    sev = _by_sev(finding.issues)
    assert "could not fingerprint host key" in sev["LOW"]
    assert any("passphrase" in m for m in sev["LOW"])
    assert sev["CRITICAL"] == ["world-accessible private key (mode 0644); sshd refuses to load it"]


def test_host_key_that_cannot_be_fingerprinted_clean_perms_only_gets_the_lows(tmp_path: Path):
    """Same undecodable host key, but mode 0600: no CRITICAL/HIGH, just the two LOWs."""
    host_key = tmp_path / "ssh_host_rsa_key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", "somepass", "-f", str(host_key)],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    audit.pub_sibling(host_key).unlink()
    host_key.chmod(0o600)

    findings = audit.audit_host_keys({"hostkey": [str(host_key)]}, min_rsa_bits=3072, owner_uid=os.getuid())
    finding = next(f for f in findings if f.path == str(host_key))
    assert (finding.key_type, finding.bits, finding.fingerprint) == ("?", 0, "")
    sev = _by_sev(finding.issues)
    assert set(sev) == {"LOW"}
    assert "could not fingerprint host key" in sev["LOW"]
    assert any("passphrase" in m for m in sev["LOW"])


def test_host_key_unreadable_group_other_bits_gets_the_sshd_refuses_suffix(tmp_path: Path):
    """Mode 0601 on a host key gets the new LOW, with the same 'sshd refuses to load it' suffix as the others."""
    host_key = tmp_path / "ssh_host_rsa_key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", str(host_key)],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    host_key.chmod(0o601)

    findings = audit.audit_host_keys({"hostkey": [str(host_key)]}, min_rsa_bits=3072, owner_uid=os.getuid())
    finding = next(f for f in findings if f.path == str(host_key))
    sev = _by_sev(finding.issues)
    assert sev["LOW"] == ["group/other bits set but not readable by them (mode 0601); sshd refuses to load it"]
    assert "CRITICAL" not in sev
    assert "HIGH" not in sev


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


def test_host_key_whose_private_half_ssh_cannot_load_is_not_fingerprinted(keys: dict[str, Path], tmp_path: Path):
    """A host key ssh cannot load is reported as unfingerprintable, however well its public half reads.

    `sshd` builds the key it serves out of the private half, so a host key whose
    private half ssh refuses to load is not a working host key -- and a matching
    `.pub` file beside it must not make it look like one.
    """
    host_key = _corrupt_the_private_half(keys["ed25519"], tmp_path / "ssh_host_ed25519_key")
    audit.pub_sibling(host_key).write_text(pub(keys["ed25519"]) + "\n")
    assert audit._ssh_keygen_would_refuse(host_key) is False  # mode 0600, so the check really runs

    findings = audit.audit_host_keys({"hostkey": [str(host_key)]}, min_rsa_bits=3072, owner_uid=os.getuid())
    finding = next(f for f in findings if f.path == str(host_key))
    assert (finding.key_type, finding.bits, finding.fingerprint) == ("?", 0, "")
    assert "could not fingerprint host key" in _by_sev(finding.issues)["LOW"]


def test_host_keys_defaults_when_unconfigured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """No HostKey configured and none of the defaults exist: sshd has no host key at all and won't start."""
    monkeypatch.setattr(audit, "DEFAULT_HOST_KEYS", [str(tmp_path / "nope")])
    findings = audit.audit_host_keys({}, min_rsa_bits=3072)
    assert [(f.path, f.key_type, f.bits, f.fingerprint) for f in findings] == [("(none)", "?", 0, "")]
    assert [(i.severity, i.message) for i in findings[0].issues] == [
        ("LOW", "no host key exists at any default path; sshd has no host key and will not start")
    ]
    # The aggregate stands on its own; it must not be followed by the Ed25519 nag too.
    assert not any("no Ed25519 host key present" in i.message for f in findings for i in f.issues)


def test_host_keys_defaults_all_unstattable_reports_only_the_stat_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A default path that could not even be stat'd must not be reported as 'no host key exists'.

    Not knowing whether the file is there is different from knowing it is not:
    the aggregate "no host key exists at any default path" finding requires
    every default path to have been confirmed absent.
    """

    def raise_permission_denied(path: Path) -> os.stat_result:
        raise OSError("permission denied")

    monkeypatch.setattr(audit, "DEFAULT_HOST_KEYS", [str(tmp_path / "nope")])
    monkeypatch.setattr(audit, "_stat_if_present", raise_permission_denied)

    findings = audit.audit_host_keys({}, min_rsa_bits=3072)

    messages = [i.message for f in findings for i in f.issues]
    assert any("could not stat host key" in m for m in messages)
    assert not any("no host key exists at any default path" in m for m in messages)


def test_host_keys_defaults_mixed_missing_and_present(
    keys: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The fallback list is used when no `HostKey` is configured: a missing entry in it is skipped silently,

    while an entry that does exist is audited exactly as a configured one would be. This is what makes it
    safe to add a new default path (such as the ML-DSA hybrid key) that most hosts do not have yet.
    """
    present = keys["ed25519"]
    monkeypatch.setattr(audit, "DEFAULT_HOST_KEYS", [str(tmp_path / "nope"), str(present)])

    findings = audit.audit_host_keys({}, min_rsa_bits=3072, owner_uid=os.getuid())

    assert [f.path for f in findings] == [str(present)]
    assert findings[0].key_type == "ED25519"
    assert not any("no host key exists at any default path" in i.message for f in findings for i in f.issues)


def test_host_key_none_on_its_own_is_reported_as_no_host_key_at_all():
    """`HostKey none` names no file, and on its own it leaves sshd with nothing to start with.

    sshd keeps `none` as a sentinel rather than a path: derelativise_path()
    hands back the literal "none" (servconf.c), fill_default_server_options()
    then clears that entry to NULL (CLEAR_ON_NONE), and the host-key loader
    skips a NULL entry (sshd.c). With no other HostKey configured, sshd exits
    with "no hostkeys available -- exiting" -- verified against OpenSSH 10.2.
    So there is no file here to look for, and nothing to say about the host's
    key types either.
    """
    findings = audit.audit_host_keys({"hostkey": ["none"]}, min_rsa_bits=3072)

    assert [(f.path, f.key_type, f.bits, f.fingerprint) for f in findings] == [("(none)", "?", 0, "")]
    assert [(i.severity, i.message) for i in findings[0].issues] == [
        (
            "LOW",
            "HostKey is set to none and no other HostKey is configured; sshd has no host key and will not start",
        )
    ]


def test_host_key_null_from_sshd_t_is_not_audited_as_a_file(keys: dict[str, Path], tmp_path: Path):
    """`sshd -T` prints a `HostKey none` entry as "hostkey (null)", which is not a path either.

    Verified against OpenSSH 10.2: a config with `HostKey none` and one real key
    prints both "hostkey (null)" and the real key's path. Only the real key is
    audited, and nothing is reported as a missing file.
    """
    ed = tmp_path / "ssh_host_ed25519_key"
    ed.write_bytes(keys["ed25519"].read_bytes())
    ed.chmod(0o600)

    findings = audit.audit_host_keys({"hostkey": ["(null)", str(ed)]}, min_rsa_bits=3072, owner_uid=os.getuid())

    assert [f.path for f in findings] == [str(ed)]
    assert findings[0].key_type == "ED25519"
    assert not any("does not exist" in i.message for f in findings for i in f.issues)


def test_host_key_none_alongside_a_real_key_leaves_the_real_key_audited(keys: dict[str, Path], tmp_path: Path):
    """The sentinel is dropped, the real key is audited, and the Ed25519 note still fires for it."""
    rsa = tmp_path / "ssh_host_rsa_key"
    rsa.write_bytes(keys["rsa4096"].read_bytes())
    rsa.chmod(0o600)

    findings = audit.audit_host_keys({"hostkey": ["none", str(rsa)]}, min_rsa_bits=3072, owner_uid=os.getuid())

    assert [f.path for f in findings] == [str(rsa), "(none)"]
    assert (findings[0].key_type, findings[0].bits) == ("RSA", 4096)
    assert findings[0].issues == []
    assert [i.message for i in findings[1].issues] == ["no Ed25519 host key present; consider ssh-keygen -A"]


@needs_non_root
def test_host_keys_unstattable_path_is_low_not_a_crash(tmp_path: Path):
    """A HostKey path this tool cannot even stat (a directory above it is unreadable) must not crash it."""
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    host_key = blocked / "ssh_host_ed25519_key"
    blocked.chmod(0o000)
    try:
        findings = audit.audit_host_keys({"hostkey": [str(host_key)]}, min_rsa_bits=3072)
    finally:
        blocked.chmod(0o700)

    finding = next(f for f in findings if f.path == str(host_key))
    assert [i.severity for i in finding.issues] == ["LOW"]
    assert finding.issues[0].message.startswith("could not stat host key")
    # Nothing was stat'd, so there is no date to report either.
    assert finding.last_modified is None


def test_host_key_reports_the_date_it_was_last_modified(keys: dict[str, Path], tmp_path: Path):
    """A key file that is there carries its date; a configured path that is not there carries none."""
    ed = tmp_path / "ssh_host_ed25519_key"
    ed.write_bytes(keys["ed25519"].read_bytes())
    ed.chmod(0o600)
    _set_mtime(ed)
    missing = tmp_path / "ssh_host_rsa_key"

    config = {"hostkey": [str(ed), str(missing)]}
    findings = audit.audit_host_keys(config, min_rsa_bits=3072, owner_uid=os.getuid())
    by_path = {f.path: f for f in findings}

    assert by_path[str(ed)].last_modified == KNOWN_DATE
    assert by_path[str(missing)].last_modified is None


def test_host_key_placeholder_entry_has_no_date():
    """A `(none)` entry names no file, so there is nothing to report a date for."""
    findings = audit.audit_host_keys({"hostkey": ["none"]}, min_rsa_bits=3072)
    assert [(f.path, f.last_modified) for f in findings] == [("(none)", None)]


HOST_KEY_ROTATION_MESSAGE = "modified within the last 7 days; confirm this was a planned rotation"


def _host_key_file(keys: dict[str, Path], tmp_path: Path, days_old: float) -> Path:
    """A clean, root-style Ed25519 host key file, backdated by a number of days."""
    hk = tmp_path / "ssh_host_ed25519_key"
    hk.write_bytes(keys["ed25519"].read_bytes())
    hk.chmod(0o600)
    return _age(hk, days_old)


def test_host_keys_changed_within_fires_only_inside_the_window(keys: dict[str, Path], tmp_path: Path):
    """The MEDIUM is on a key modified inside the window, and on nothing else.

    All three halves are checked against the same otherwise-clean key file: a
    key changed two days ago with a seven-day window, the same key aged past
    the window, and the same key with the option left off, which is the
    default.
    """
    hk = _host_key_file(keys, tmp_path, days_old=2)
    config = {"hostkey": [str(hk)]}

    recent = audit.audit_host_keys(config, 3072, owner_uid=os.getuid(), changed_within_days=7, now=NOW)
    finding = next(f for f in recent if f.path == str(hk))
    assert [(i.severity, i.message) for i in finding.issues] == [("MEDIUM", HOST_KEY_ROTATION_MESSAGE)]

    _age(hk, 10)
    older = audit.audit_host_keys(config, 3072, owner_uid=os.getuid(), changed_within_days=7, now=NOW)
    assert next(f for f in older if f.path == str(hk)).issues == []

    _age(hk, 2)
    off = audit.audit_host_keys(config, 3072, owner_uid=os.getuid(), now=NOW)
    assert next(f for f in off if f.path == str(hk)).issues == []


def test_host_keys_changed_within_fires_on_a_public_key_file_with_and_without_an_agent(
    keys: dict[str, Path], tmp_path: Path
):
    """A HostKey naming a public key file is still a file with a modification time.

    sshd loads that entry (through HostKeyAgent) or does not, but either way
    the file changing is what the operator asked to hear about, so both shapes
    of finding carry the MEDIUM alongside whatever they already said.
    """
    hk = tmp_path / "ssh_host_ed25519_key.pub"
    hk.write_text(pub(keys["ed25519"]) + "\n")
    hk.chmod(0o644)
    _age(hk, 2)

    with_agent = audit.audit_host_keys(
        {"hostkey": [str(hk)], "hostkeyagent": ["/run/host-key-agent.sock"]},
        3072,
        owner_uid=os.getuid(),
        changed_within_days=7,
        now=NOW,
    )
    finding = next(f for f in with_agent if f.path == str(hk))
    assert [(i.severity, i.message) for i in finding.issues] == [
        ("INFO", "public key file; the private half is held by HostKeyAgent and cannot be audited here"),
        ("MEDIUM", HOST_KEY_ROTATION_MESSAGE),
    ]

    without_agent = audit.audit_host_keys(
        {"hostkey": [str(hk)]}, 3072, owner_uid=os.getuid(), changed_within_days=7, now=NOW
    )
    finding = next(f for f in without_agent if f.path == str(hk))
    assert [(i.severity, i.message) for i in finding.issues] == [
        ("LOW", "HostKey names a public key file and no HostKeyAgent is set; sshd cannot load a private key from it"),
        ("MEDIUM", HOST_KEY_ROTATION_MESSAGE),
    ]


def test_host_keys_changed_within_fires_on_a_certificate_file(tmp_path: Path):
    """A HostKey naming a certificate is unusable to sshd, but the file still changed."""
    cert = _age(_ed25519_host_certificate(tmp_path, "ssh_host_ed25519_key"), 2)

    findings = audit.audit_host_keys(
        {"hostkey": [str(cert)]}, 3072, owner_uid=os.getuid(), changed_within_days=7, now=NOW
    )

    finding = next(f for f in findings if f.path == str(cert))
    assert [(i.severity, i.message) for i in finding.issues] == [
        (
            "LOW",
            "HostKey names a certificate file; sshd cannot load a host key from it "
            "(a certificate belongs on a HostCertificate line)",
        ),
        ("MEDIUM", HOST_KEY_ROTATION_MESSAGE),
    ]


def test_host_keys_changed_within_says_nothing_about_an_entry_with_no_file(keys: dict[str, Path], tmp_path: Path):
    """A configured key that is not there, and a `(none)` placeholder, have no modification time.

    The placeholder has to actually be in the findings for the claim to mean
    anything: `HostKey none` is dropped before any finding is built, so the
    two placeholders that do get built are used instead -- the Ed25519 note
    that follows a host with only an RSA key, and the entry for a host whose
    only HostKey is `none`. A recently modified RSA key sits alongside the
    first, so the option is demonstrably doing something in the same run.
    """
    present = tmp_path / "ssh_host_rsa_key"
    present.write_bytes(keys["rsa4096"].read_bytes())
    present.chmod(0o600)
    _age(present, 2)
    missing = tmp_path / "ssh_host_ecdsa_key"

    findings = audit.audit_host_keys(
        {"hostkey": [str(present), str(missing)]}, 3072, owner_uid=os.getuid(), changed_within_days=7, now=NOW
    )

    by_path = {f.path: f for f in findings}
    assert [i.message for i in by_path[str(present)].issues] == [HOST_KEY_ROTATION_MESSAGE]
    assert [i.message for i in by_path[str(missing)].issues] == ["configured HostKey does not exist"]
    assert [(i.severity, i.message) for i in by_path["(none)"].issues] == [
        ("LOW", "no Ed25519 host key present; consider ssh-keygen -A")
    ]

    none_only = audit.audit_host_keys({"hostkey": ["none"]}, 3072, changed_within_days=7, now=NOW)
    assert [(f.path, [(i.severity, i.message) for i in f.issues]) for f in none_only] == [
        (
            "(none)",
            [
                (
                    "LOW",
                    "HostKey is set to none and no other HostKey is configured; "
                    "sshd has no host key and will not start",
                )
            ],
        )
    ]


@needs_non_root
def test_host_keys_changed_within_says_nothing_about_a_key_that_cannot_be_stat_d(tmp_path: Path):
    """No stat means no modification time, so the option cannot say anything about the file."""
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    host_key = blocked / "ssh_host_ed25519_key"
    host_key.write_text("not read\n")
    _age(host_key, 2)
    blocked.chmod(0o000)
    try:
        findings = audit.audit_host_keys(
            {"hostkey": [str(host_key)]}, 3072, owner_uid=os.getuid(), changed_within_days=7, now=NOW
        )
    finally:
        blocked.chmod(0o700)

    finding = next(f for f in findings if f.path == str(host_key))
    assert [i.severity for i in finding.issues] == ["LOW"]
    assert finding.issues[0].message.startswith("could not stat host key")


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


@needs_non_root
def test_authorized_keys_unstattable_home_is_a_file_finding_not_a_crash(keys: dict[str, Path], tmp_path: Path):
    """A home this tool cannot even stat (another account's home when not running as root) must not crash it.

    Regression test for a crash: os.stat() on a path below a 0o000 directory
    raises PermissionError on Python 3.10-3.12, and without the fix that
    propagated straight out of audit_authorized_keys as an unhandled
    exception. A second account with a normal, readable file is included to
    prove the rest of the run is unaffected.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID + 1, tmp_path / "home" / "bob")
    Path(alice.pw_dir).mkdir(parents=True, mode=0o700)
    Path(bob.pw_dir).mkdir(parents=True, mode=0o700)
    _write_ak(bob, [pub(keys["ed25519"])])
    Path(alice.pw_dir).chmod(0o000)

    config = {"authorizedkeysfile": [".ssh/authorized_keys"]}  # a single pattern keeps this test to one file
    try:
        _, files, ak, _, _ = audit.audit_authorized_keys(config, 3072, users=[alice, bob])
    finally:
        Path(alice.pw_dir).chmod(0o700)

    alice_files = [f for f in files if f.user == "alice"]
    assert len(alice_files) == 1
    assert alice_files[0].key_count == 0
    assert [i.severity for i in alice_files[0].issues] == ["LOW"]
    assert alice_files[0].issues[0].message.startswith(f"could not stat {alice_files[0].file_path}")
    assert alice_files[0].last_modified is None  # nothing was stat'd, so there is no date
    assert not any(k.user == "alice" for k in ak)

    assert any(k.user == "bob" for k in ak)  # the other account was still audited normally


def test_authorized_keys_file_and_every_key_in_it_carry_the_file_date(keys: dict[str, Path], tmp_path: Path):
    alice = make_user("alice", USER_UID, tmp_path / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    ak_path = _write_ak(alice, [pub(keys["ed25519"]), pub(keys["rsa4096"])])
    _set_mtime(ak_path)

    _, files, ak, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert [f.last_modified for f in files] == [KNOWN_DATE]
    assert len(ak) == 2
    assert [k.file_last_modified for k in ak] == [KNOWN_DATE, KNOWN_DATE]


def test_authorized_keys_symlink_reports_the_date_of_the_file_sshd_reads(keys: dict[str, Path], tmp_path: Path):
    """Path.stat() follows symlinks, so the date is the target's, not the link's."""
    alice = make_user("alice", USER_UID, tmp_path / "alice")
    ssh_dir = mkdir_clean(Path(alice.pw_dir) / ".ssh", tmp_path, mode=0o700)
    target = ssh_dir / "authorized_keys.real"
    target.write_text(pub(keys["ed25519"]) + "\n")
    target.chmod(0o600)
    _set_mtime(target)
    link = ssh_dir / "authorized_keys"
    link.symlink_to(target)
    # The link's own timestamp is a different date, so a check that read the
    # link instead of its target would report 1999-01-02 here.
    link_mtime = datetime(1999, 1, 2, 12).timestamp()
    os.utime(link, (link_mtime, link_mtime), follow_symlinks=False)

    _, files, ak, _, _ = audit.audit_authorized_keys(
        {"authorizedkeysfile": [".ssh/authorized_keys"]}, 3072, users=[alice]
    )

    assert [f.last_modified for f in files] == [KNOWN_DATE]
    assert [k.file_last_modified for k in ak] == [KNOWN_DATE]


ONE_PATTERN = {"authorizedkeysfile": [".ssh/authorized_keys"]}  # a single pattern keeps these tests to one file


def _account_with_authorized_keys(tmp_path: Path, lines: list[str], days_old: float) -> pwd.struct_passwd:
    """An account whose authorized_keys file holds the given lines and was last modified that long ago."""
    alice = make_user("alice", USER_UID, tmp_path / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _age(_write_ak(alice, lines), days_old)
    return alice


def _one_file_finding(
    user: pwd.struct_passwd, *, changed_within_days: int | None = None, unchanged_for_days: int | None = None
) -> audit.FileFinding:
    """The single file finding for an account, audited at the fixed NOW.

    Passing neither threshold is how the tests check that a file is left alone
    when the options are off, which is the default.
    """
    _, files, _, _, _ = audit.audit_authorized_keys(
        ONE_PATTERN,
        3072,
        users=[user],
        now=NOW,
        changed_within_days=changed_within_days,
        unchanged_for_days=unchanged_for_days,
    )
    assert len(files) == 1
    return files[0]


def test_authorized_keys_changed_within_fires_only_inside_the_window(keys: dict[str, Path], tmp_path: Path):
    """The MEDIUM is on a file modified inside the window, and on nothing else.

    The same otherwise-clean file is audited three ways: changed two days ago
    with a seven-day window, aged past that window, and with the option left
    off, which is the default.
    """
    alice = _account_with_authorized_keys(tmp_path, [pub(keys["ed25519"])], days_old=2)
    ak = Path(alice.pw_dir) / ".ssh" / "authorized_keys"

    inside = _one_file_finding(alice, changed_within_days=7)
    assert [(i.severity, i.message) for i in inside.issues] == [
        ("MEDIUM", "modified within the last 7 days; confirm the change was expected")
    ]

    _age(ak, 10)
    outside = _one_file_finding(alice, changed_within_days=7)
    assert outside.issues == []

    _age(ak, 2)
    assert _one_file_finding(alice).issues == []


def test_authorized_keys_changed_within_fires_on_a_file_holding_no_keys(tmp_path: Path):
    """A file emptied out or cut down to comments has changed, which is the thing being watched for."""
    alice = _account_with_authorized_keys(tmp_path, ["# every key was removed this morning"], days_old=2)

    finding = _one_file_finding(alice, changed_within_days=7)

    assert finding.key_count == 0
    assert [(i.severity, i.message) for i in finding.issues] == [
        ("MEDIUM", "modified within the last 7 days; confirm the change was expected")
    ]


@needs_non_root
def test_authorized_keys_changed_within_fires_on_a_file_that_cannot_be_read(keys: dict[str, Path], tmp_path: Path):
    """The check is decided from the stat, so a file whose contents are out of reach still gets it."""
    alice = _account_with_authorized_keys(tmp_path, [pub(keys["ed25519"])], days_old=2)
    ak = Path(alice.pw_dir) / ".ssh" / "authorized_keys"
    ak.chmod(0o000)
    try:
        finding = _one_file_finding(alice, changed_within_days=7, unchanged_for_days=1)
    finally:
        ak.chmod(0o600)

    assert finding.key_count == 0
    assert [i.severity for i in finding.issues] == ["MEDIUM", "LOW"]
    assert finding.issues[0].message == "modified within the last 7 days; confirm the change was expected"
    assert finding.issues[1].message.startswith("could not read file: ")
    # Nothing is known about what the file authorises, so it cannot be called stale
    # either, even though the unchanged-for window it was given is one day.
    assert not any("not modified in" in i.message for i in finding.issues)


@needs_non_root
def test_authorized_keys_thresholds_say_nothing_about_a_file_that_cannot_be_stat_d(
    keys: dict[str, Path], tmp_path: Path
):
    """No stat means no modification time, so neither threshold can say anything about the file."""
    alice = _account_with_authorized_keys(tmp_path, [pub(keys["ed25519"])], days_old=2)
    Path(alice.pw_dir).chmod(0o000)
    try:
        finding = _one_file_finding(alice, changed_within_days=7, unchanged_for_days=1)
    finally:
        Path(alice.pw_dir).chmod(0o700)

    assert [i.severity for i in finding.issues] == ["LOW"]
    assert finding.issues[0].message.startswith("could not stat ")


def test_authorized_keys_unchanged_for_fires_only_outside_the_window(keys: dict[str, Path], tmp_path: Path):
    """The LOW is on a file that has gone untouched for longer than the window, and on nothing else."""
    alice = _account_with_authorized_keys(tmp_path, [pub(keys["ed25519"])], days_old=40)
    ak = Path(alice.pw_dir) / ".ssh" / "authorized_keys"

    stale = _one_file_finding(alice, unchanged_for_days=30)
    assert [(i.severity, i.message) for i in stale.issues] == [
        ("LOW", "not modified in 30 days; review whether every key in it should still have access")
    ]

    _age(ak, 10)
    recent = _one_file_finding(alice, unchanged_for_days=30)
    assert recent.issues == []

    _age(ak, 40)
    assert _one_file_finding(alice).issues == []


def test_authorized_keys_unchanged_for_says_nothing_about_a_file_with_no_working_key(tmp_path: Path):
    """A file nobody can log in with says nothing about how old anyone's access is.

    A file holding only comments and a file holding only a certificate line are
    both in that position: sshd never matches a certificate blob in
    authorized_keys, so such a line grants nobody anything even though it is
    counted as a key entry in the report.
    """
    _, certificate_line = _ed25519_certificate(tmp_path, "cert-only", "alice")
    comments_only = _account_with_authorized_keys(tmp_path / "comments", ["# nothing here"], days_old=40)
    cert_only = _account_with_authorized_keys(tmp_path / "cert", [certificate_line], days_old=40)

    assert _one_file_finding(comments_only, unchanged_for_days=30).issues == []
    cert_finding = _one_file_finding(cert_only, unchanged_for_days=30)
    assert cert_finding.key_count == 1  # the line is counted, but it authorises nobody
    assert cert_finding.issues == []


def test_authorized_keys_unchanged_for_fires_on_a_file_whose_only_working_key_sits_beside_a_certificate(
    keys: dict[str, Path], tmp_path: Path
):
    """One working key is enough, however many inert lines keep it company."""
    _, certificate_line = _ed25519_certificate(tmp_path, "cert", "alice")
    alice = _account_with_authorized_keys(tmp_path, [certificate_line, pub(keys["ed25519"])], days_old=40)

    finding = _one_file_finding(alice, unchanged_for_days=30)

    assert [(i.severity, i.message) for i in finding.issues] == [
        ("LOW", "not modified in 30 days; review whether every key in it should still have access")
    ]


def test_authorized_keys_both_thresholds_at_once_give_each_file_exactly_one_of_them(
    keys: dict[str, Path], tmp_path: Path
):
    """With the same window, a file is either recently changed or stale, never both and never neither."""
    recent = _account_with_authorized_keys(tmp_path / "recent", [pub(keys["ed25519"])], days_old=2)
    stale = _account_with_authorized_keys(tmp_path / "stale", [pub(keys["rsa4096"])], days_old=10)

    recent_finding = _one_file_finding(recent, changed_within_days=7, unchanged_for_days=7)
    stale_finding = _one_file_finding(stale, changed_within_days=7, unchanged_for_days=7)

    assert [(i.severity, i.message) for i in recent_finding.issues] == [
        ("MEDIUM", "modified within the last 7 days; confirm the change was expected")
    ]
    assert [(i.severity, i.message) for i in stale_finding.issues] == [
        ("LOW", "not modified in 7 days; review whether every key in it should still have access")
    ]


def test_authorized_keys_thresholds_use_the_singular_for_a_one_day_window(keys: dict[str, Path], tmp_path: Path):
    """The messages are built from a day count, so a window of one day has to read as English."""
    recent = _account_with_authorized_keys(tmp_path / "recent", [pub(keys["ed25519"])], days_old=0.5)
    stale = _account_with_authorized_keys(tmp_path / "stale", [pub(keys["rsa4096"])], days_old=3)

    assert [i.message for i in _one_file_finding(recent, changed_within_days=1).issues] == [
        "modified within the last 1 day; confirm the change was expected"
    ]
    assert [i.message for i in _one_file_finding(stale, unchanged_for_days=1).issues] == [
        "not modified in 1 day; review whether every key in it should still have access"
    ]


def test_authorized_keys_certificate_is_reported_as_inert_not_graded(tmp_path: Path):
    """A line whose own blob is a certificate never matches in sshd, so grading it would be misleading.

    auth_check_authkey_line() (auth2-pubkeyfile.c) matches a plain presented
    key only against the line itself, and a presented certificate only
    against a cert-authority line holding the CA's plain key -- a line that
    IS a certificate satisfies neither, so it grants no access regardless of
    the key inside it. Grading must be skipped for it, and only for it: a
    separate plain line with an equally weak key in the same file must still
    be graded normally. (The cert and the key it certifies fingerprint
    identically -- `ssh-keygen -l` reports the same SHA256 for both -- so a
    distinct plain key is used here to keep this test clear of the separate
    duplicate-key detection.)
    """
    alice = make_user("alice", USER_UID, tmp_path / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)

    def keygen_rsa(name: str, bits: int) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["ssh-keygen", "-q", "-t", "rsa", "-b", str(bits), "-N", "", "-f", str(tmp_path / name)],
            capture_output=True,
            stdin=subprocess.DEVNULL,
        )

    ca = tmp_path / "ca"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(ca)],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )

    # 1024 bits so a CRITICAL is expected on the plain line -- and, since
    # --min-rsa-bits can never lower that floor, grading being skipped for the
    # certificate line is unmistakable rather than a coincidence of policy.
    bits, min_rsa_bits, expected_plain_severity = 1024, 3072, "CRITICAL"
    user_name, plain_name = "user1024", "plain1024"
    if keygen_rsa(user_name, bits).returncode != 0 or keygen_rsa(plain_name, bits).returncode != 0:
        # Some ssh-keygen builds refuse to generate a 1024-bit RSA key; fall
        # back to a size that is still weak against a raised policy minimum,
        # using fresh filenames so a half-written 1024-bit attempt is never
        # in the way of ssh-keygen's overwrite prompt.
        bits, min_rsa_bits, expected_plain_severity = 2048, 4096, "MEDIUM"
        user_name, plain_name = "user2048", "plain2048"
        assert keygen_rsa(user_name, bits).returncode == 0
        assert keygen_rsa(plain_name, bits).returncode == 0

    user_key = tmp_path / user_name
    subprocess.run(
        ["ssh-keygen", "-q", "-s", str(ca), "-I", "test", "-n", "alice", str(user_key) + ".pub"],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    cert_line = (tmp_path / f"{user_name}-cert.pub").read_text().strip()
    plain_line = pub(tmp_path / plain_name)

    _write_ak(alice, [plain_line, cert_line])
    _, _, findings, _, _ = audit.audit_authorized_keys({}, min_rsa_bits, users=[alice])
    by_line = {f.line_number: f for f in findings}

    cert_finding = by_line[2]
    assert cert_finding.key_type == "RSA-CERT"
    assert [i.severity for i in cert_finding.issues] == ["INFO"]
    assert cert_finding.issues[0].message == (
        "certificate listed in authorized_keys; sshd never matches a certificate here, so this line grants no access"
    )

    plain_finding = by_line[1]
    assert plain_finding.key_type == "RSA"
    assert [i.severity for i in plain_finding.issues] == [expected_plain_severity]


def _ed25519_certificate(tmp_path: Path, name: str, principal: str) -> tuple[str, str]:
    """Sign a fresh ed25519 key with a fresh CA.

    Returns (plain public-key line, certificate line). `ssh-keygen -l` reports
    a certificate under the fingerprint of the key inside it, so the two lines
    fingerprint identically -- which is exactly what the reuse checks have to
    cope with.
    """

    def keygen(path: Path) -> None:
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
            check=True,
            capture_output=True,
            stdin=subprocess.DEVNULL,
        )

    ca = tmp_path / f"{name}-ca"
    user_key = tmp_path / name
    keygen(ca)
    keygen(user_key)
    subprocess.run(
        ["ssh-keygen", "-q", "-s", str(ca), "-I", "test", "-n", principal, str(user_key) + ".pub"],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    return pub(user_key), (tmp_path / f"{name}-cert.pub").read_text().strip()


def test_certificate_line_is_not_reported_as_the_inner_key_reused(tmp_path: Path):
    """A certificate for one account and the key it certifies for another is not key reuse.

    `ssh-keygen -l` gives a certificate the fingerprint of the key inside it,
    so counting a certificate line would make the two look like one key shared
    between two accounts -- while the certificate line actually grants nothing.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID, tmp_path / "home" / "bob")
    for u in (alice, bob):
        mkdir_clean(Path(u.pw_dir), tmp_path)
    plain_line, cert_line = _ed25519_certificate(tmp_path, "shared", "alice")
    _write_ak(alice, [cert_line])
    _write_ak(bob, [plain_line])

    _, _, found, dupes, _ = audit.audit_authorized_keys({}, 3072, users=[alice, bob])

    assert dupes == {}
    assert not any("same key" in i.message for f in found for i in f.issues)
    by_user = {f.user: f for f in found}
    assert by_user["alice"].key_type == "ED25519-CERT"
    assert [i.severity for i in by_user["alice"].issues] == ["INFO"]
    assert by_user["bob"].issues == []


def test_certificate_line_is_skipped_when_the_inner_key_is_shared_by_two_other_accounts(tmp_path: Path):
    """Real reuse between two accounts is still reported, and the certificate stays out of it.

    (The plain negative half -- one key in two accounts' files getting a
    MEDIUM -- is covered by
    test_key_shared_between_accounts_is_medium_even_when_also_listed_twice.)
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID, tmp_path / "home" / "bob")
    carol = make_user("carol", USER_UID, tmp_path / "home" / "carol")
    for u in (alice, bob, carol):
        mkdir_clean(Path(u.pw_dir), tmp_path)
    plain_line, cert_line = _ed25519_certificate(tmp_path, "shared", "alice")
    _write_ak(alice, [cert_line])
    bob_ak = _write_ak(bob, [plain_line])
    carol_ak = _write_ak(carol, [plain_line])

    _, _, found, dupes, _ = audit.audit_authorized_keys({}, 3072, users=[alice, bob, carol])

    by_user = {f.user: f for f in found}
    fingerprint = by_user["bob"].fingerprint
    assert set(dupes) == {fingerprint}
    assert sorted(dupes[fingerprint]) == sorted([f"bob {bob_ak}:1", f"carol {carol_ak}:1"])
    assert _by_sev(by_user["bob"].issues)["MEDIUM"] == [f"same key also authorized at: carol {carol_ak}:1"]
    assert _by_sev(by_user["carol"].issues)["MEDIUM"] == [f"same key also authorized at: bob {bob_ak}:1"]
    assert [i.severity for i in by_user["alice"].issues] == ["INFO"]


def test_authorized_keys_line_with_a_typo_in_an_option_is_reported_not_counted(keys: dict[str, Path], tmp_path: Path):
    """sshd throws away a whole line whose options do not parse, so the key must not be counted."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [pub(keys["ed25519"]), f"no-port-fowarding {pub(keys['rsa4096'])}"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    alice_file = files[0]
    assert alice_file.key_count == 1
    assert _by_sev(alice_file.issues)["LOW"] == [
        'line 2: bad key options (unknown key option "no-port-fowarding"); sshd rejects the whole line'
    ]
    assert [f.line_number for f in found] == [1]


def test_a_key_on_a_rejected_line_is_not_counted_as_reused(keys: dict[str, Path], tmp_path: Path):
    """A dead line must not make a legitimate key elsewhere look shared between accounts."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID, tmp_path / "home" / "bob")
    for u in (alice, bob):
        mkdir_clean(Path(u.pw_dir), tmp_path)
    _write_ak(alice, [pub(keys["ed25519"])])
    _write_ak(bob, [f"no-port-fowarding {pub(keys['ed25519'])}"])

    _, files, found, dupes, _ = audit.audit_authorized_keys({}, 3072, users=[alice, bob])

    assert dupes == {}
    assert [(f.user, f.line_number) for f in found] == [("alice", 1)]
    assert not any("same key" in i.message for i in found[0].issues)
    bob_file = next(f for f in files if f.user == "bob")
    assert bob_file.key_count == 0
    assert _by_sev(bob_file.issues)["LOW"] == [
        'line 1: bad key options (unknown key option "no-port-fowarding"); sshd rejects the whole line'
    ]


def test_authorized_keys_leading_comma_is_accepted_and_counted(keys: dict[str, Path], tmp_path: Path):
    """sshd's option loop skips the empty token left by a leading comma and accepts the line; a live OpenSSH
    10.2 login confirmed ",no-pty <key>" is accepted."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [f",no-pty {pub(keys['ed25519'])}"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].key_count == 1
    assert not any("bad key options" in i.message for i in files[0].issues)
    assert len(found) == 1
    assert found[0].options == ["no-pty"]


def test_authorized_keys_doubled_comma_is_accepted_and_counted(keys: dict[str, Path], tmp_path: Path):
    """Same reasoning as the leading-comma case; a live OpenSSH 10.2 login confirmed "no-pty,,restrict <key>"
    is accepted."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [f"no-pty,,restrict {pub(keys['ed25519'])}"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].key_count == 1
    assert not any("bad key options" in i.message for i in files[0].issues)
    assert len(found) == 1
    assert found[0].options == ["no-pty", "restrict"]


def test_authorized_keys_unknown_option_after_a_comma_is_still_rejected(keys: dict[str, Path], tmp_path: Path):
    """An empty token is skipped, but a real unmatched token still gets the whole line thrown out; a live
    OpenSSH 10.2 login confirmed "no-pty,bogus <key>" is rejected."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [f"no-pty,bogus {pub(keys['ed25519'])}"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert found == []
    assert files[0].key_count == 0
    assert _by_sev(files[0].issues)["LOW"] == [
        'line 1: bad key options (unknown key option "bogus"); sshd rejects the whole line'
    ]


def test_authorized_keys_trailing_comma_before_the_key_is_accepted(keys: dict[str, Path], tmp_path: Path):
    """A comma right before the key is sshd's option loop stopping, not an empty option -- the line is fine."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [f"no-pty, {pub(keys['ed25519'])}"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].key_count == 1
    assert not any("bad key options" in i.message for i in files[0].issues)
    assert len(found) == 1
    assert found[0].options == ["no-pty"]


def test_authorized_keys_principals_without_cert_authority_is_reported_not_counted(
    keys: dict[str, Path], tmp_path: Path
):
    """sshd denies a line that lists principals on a key it is not told is a CA.

    auth_authorise_keyopts() (auth2-pubkeyfile.c) turns such a line down with
    "principals on non-CA key", so the key on it authorises nobody. The same
    options with cert-authority beside them are fine, and that line is counted.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(
        alice,
        [
            f'principals="admin" {pub(keys["ed25519"])}',
            f'cert-authority,principals="admin" {pub(keys["rsa4096"])}',
        ],
    )

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].key_count == 1
    assert _by_sev(files[0].issues)["LOW"] == [
        "line 1: bad key options (principals on non-CA key); sshd rejects the whole line"
    ]
    assert [f.line_number for f in found] == [2]


def test_authorized_keys_rich_valid_options_are_counted_and_graded(keys: dict[str, Path], tmp_path: Path):
    """The clean case: every option shape sshd accepts leaves the line counted and graded as usual."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [f"{RICH_VALID_OPTIONS} {pub(keys['ed25519'])}"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].key_count == 1
    assert not any("bad key options" in i.message for i in files[0].issues)
    assert len(found) == 1
    assert found[0].issues == []
    assert found[0].options[0] == "restrict"
    assert found[0].options[1] == 'command="echo \\"hi\\",there"'


def test_authorized_keys_unclosed_quote_is_reported_as_bad_options(keys: dict[str, Path], tmp_path: Path):
    """An unclosed quote eats the key material, and sshd turns the line down over its options.

    split_options keeps reading to the end of the line while a quote is open,
    so nothing is left that could be read as a key. Calling the result an
    unparseable entry would point at the wrong half of the line: sshd's own
    complaint is "bad key options: missing end quote".
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [f'command="echo hi {pub(keys["ed25519"])}'])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert found == []
    assert files[0].key_count == 0
    assert _by_sev(files[0].issues)["LOW"] == [
        "line 1: bad key options (missing end quote); sshd rejects the whole line"
    ]


def test_unparseable_key_material_with_bad_options_reports_only_the_unparseable_entry(tmp_path: Path):
    """sshd never looks at the options of a line whose key it cannot read, so neither does the tool."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, ["no-port-fowarding ssh-rsa notreallyakey garbage@x"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert found == []
    assert files[0].key_count == 0
    assert _by_sev(files[0].issues)["LOW"] == ["line 1: unparseable entry (ignored by sshd)"]


@pytest.mark.parametrize(
    "prefix", ["somehost", "@cert-authority", "@revoked", "*.example.com", "192.0.2.1,host.example"]
)
def test_authorized_keys_known_hosts_syntax_after_the_options_is_not_a_working_key(
    keys: dict[str, Path], tmp_path: Path, prefix: str
):
    """sshd reads the key at exactly this offset, and `ssh-keygen -l` is more forgiving than it is.

    After the options, sshd calls sshkey_read() (auth2-pubkeyfile.c) and
    ignores the line when it fails -- and it fails on every shape of
    known_hosts line, because the field where the key type belongs holds a host
    name, a host pattern, or a marker instead. `ssh-keygen -lf -` accepts
    known_hosts lines as well as authorized_keys lines, so it printed a
    fingerprint for each of these, and the line was reported as a key granting
    access that it grants to nobody -- and entered in the comparison for keys
    reused across accounts, which is the negative half checked here through
    bob, who really is authorised for this key.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID, tmp_path / "home" / "bob")
    for u in (alice, bob):
        mkdir_clean(Path(u.pw_dir), tmp_path)
    # A valid option in front, so that the line is turned down over the key
    # material rather than over an option sshd does not know.
    _write_ak(alice, [f"no-pty {prefix} {pub(keys['ed25519'])}"])
    _write_ak(bob, [pub(keys["ed25519"])])

    _, files, found, dupes, _ = audit.audit_authorized_keys({}, 3072, users=[alice, bob])

    by_user = {f.user: f for f in files}
    assert by_user["alice"].key_count == 0
    assert _by_sev(by_user["alice"].issues)["LOW"] == ["line 1: unparseable entry (ignored by sshd)"]
    assert [f.user for f in found] == ["bob"]
    assert dupes == {}
    assert found[0].issues == []


def test_authorized_keys_certificate_line_still_parses_with_and_without_options(tmp_path: Path):
    """A certificate line has to keep working now that key material is held to sshd's own test.

    That test asks whether the second field is a key blob naming the type in
    the first field, which a certificate satisfies exactly as a plain key does:
    its blob names its own certificate type. Both shapes of line are checked,
    because the test is applied to what is left after any options.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _, cert_line = _ed25519_certificate(tmp_path, "still-parses", "alice")
    assert audit._is_bare_key_line(cert_line) is True
    _write_ak(alice, [cert_line, f"no-pty {cert_line}"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].issues == []
    assert files[0].key_count == 2
    assert [f.line_number for f in found] == [1, 2]
    assert {f.key_type for f in found} == {"ED25519-CERT"}
    assert [i.severity for f in found for i in f.issues] == ["INFO", "INFO"]


@pytest.mark.parametrize(
    ("name", "character"),
    [
        ("vertical tab", "\v"),
        ("form feed", "\f"),
        ("file separator", "\x1c"),
        ("next line", "\x85"),
        ("line separator", "\u2028"),
    ],
)
def test_authorized_keys_line_numbers_survive_a_character_sshd_does_not_break_lines_on(
    keys: dict[str, Path], tmp_path: Path, name: str, character: str
):
    """sshd's getline() ends a line at a newline and nothing else, so neither may this tool.

    Python's line splitting breaks on every one of them, so a single one in a
    key comment -- which the account owning the file chooses -- used to split
    that line in two: every line number after it was reported one too high,
    pointing the operator at the wrong line to delete, and the tail end of the
    comment was reported as an entry of its own that sshd never sees.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    key_line = f"{pub(keys['ed25519']).rsplit(' ', 1)[0]} co{character}mment"
    _write_ak(alice, [key_line, "ssh-rsa notreallyakey garbage@x"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].key_count == 1
    assert [f.line_number for f in found] == [1]
    assert _by_sev(files[0].issues)["LOW"] == ["line 2: unparseable entry (ignored by sshd)"]


def test_authorized_keys_line_starting_with_a_non_breaking_space_is_not_a_key(keys: dict[str, Path], tmp_path: Path):
    """sshd skips a space and a tab at the start of a line, and nothing else.

    A non-breaking space is left where it is, so it becomes part of the field
    where the key type belongs and sshd reads no key from the line at all.
    str.strip() removed it, which turned a line sshd throws away into a key the
    report counted and graded.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [f"\u00a0{pub(keys['ed25519'])}"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert found == []
    assert files[0].key_count == 0
    assert _by_sev(files[0].issues)["LOW"] == ["line 1: unparseable entry (ignored by sshd)"]


class _FailsAfterTheFirstLine:
    """A file object that hands over line 1, then reports an I/O error on the next read."""

    def __init__(self, wrapped: TextIO) -> None:
        self._wrapped = wrapped
        self._lines_read = 0

    def readline(self, size: int = -1) -> str:
        self._lines_read += 1
        if self._lines_read > 1:
            raise OSError("Input/output error")
        return self._wrapped.readline(size)

    def close(self) -> None:
        self._wrapped.close()


class _FailsOnClose:
    """A file object that reads to the end normally and then reports an I/O error when it is closed."""

    def __init__(self, wrapped: TextIO) -> None:
        self._wrapped = wrapped

    def readline(self, size: int = -1) -> str:
        return self._wrapped.readline(size)

    def close(self) -> None:
        self._wrapped.close()
        raise OSError("Input/output error")


def _patch_open(monkeypatch: pytest.MonkeyPatch, target: Path, stand_in: Callable[[TextIO], Any]) -> None:
    """Make Path.open hand back `stand_in(real handle)` for one file, and the real handle for all others."""
    real_open = Path.open

    def fake_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        handle = real_open(self, *args, **kwargs)
        return stand_in(handle) if self == target else handle

    monkeypatch.setattr(Path, "open", fake_open)


@pytest.mark.parametrize("indent", [" ", "\t", "  \t "])
def test_authorized_keys_line_indented_with_spaces_or_tabs_is_still_a_key(
    keys: dict[str, Path], tmp_path: Path, indent: str
):
    """The other half of the claim in the test above: sshd does skip a space and a tab.

    auth_check_authkeys_file() (auth2-pubkeyfile.c) calls skip_space()
    (misc.c), which steps over exactly ' ' and '\t' and stops at anything
    else, before it reads the key. So an indented key line authorises its
    account and this tool has to count it, however many of those two
    characters are in front of it -- while the non-breaking space in the test
    above is left where it is. Both shapes of line are indented here, because
    a line with options and a line without take different paths through
    split_options.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [f"{indent}{pub(keys['ed25519'])}", f"{indent}no-pty {pub(keys['rsa4096'])}"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].issues == []
    assert files[0].key_count == 2
    assert [(f.line_number, f.key_type) for f in found] == [(1, "ED25519"), (2, "RSA")]
    assert found[1].options == ["no-pty"]


@pytest.mark.parametrize("marker", ["@cert-authority", "@revoked"])
def test_authorized_keys_marker_before_a_host_pattern_is_an_unparseable_entry(
    keys: dict[str, Path], tmp_path: Path, marker: str
):
    """These lines changed which finding they get, and the new one is what sshd's own control flow implies.

    `@cert-authority *.example.com <key>`, and the same with known_hosts'
    other marker, used to be reported as bad key options -- `unknown key
    option "@cert-authority"` -- because the options were checked as soon as
    `ssh-keygen -l` had fingerprinted what came after the marker, which it
    does, since it accepts known_hosts syntax. sshd never reaches its option
    parser for such a line: auth_check_authkey_line() (auth2-pubkeyfile.c)
    does `goto out` when the second sshkey_read() fails, without calling
    sshauthopt_parse() at all. So the honest report is that sshd read no key
    from the line, and that is what an operator now sees.

    The same marker with no host pattern after it -- `@cert-authority <key>`
    -- still reads as an option in front of a real key, and is still reported
    as a bad option; docs/findings.md says which shapes go where.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [f"{marker} *.example.com {pub(keys['ed25519'])}"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert found == []
    assert files[0].key_count == 0
    assert _by_sev(files[0].issues)["LOW"] == ["line 1: unparseable entry (ignored by sshd)"]


@pytest.mark.parametrize("marker", ["@cert-authority", "@revoked"])
def test_authorized_keys_marker_with_no_host_pattern_is_a_bad_option(
    keys: dict[str, Path], tmp_path: Path, marker: str
):
    """The other half: with no host pattern behind it, the marker is an option in front of a real key.

    sshd reads the key fine at that offset and then turns the line down over
    the option, which is not one it knows, so the bad-options finding is the
    right one here and the row in docs/findings.md says so.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [f"{marker} {pub(keys['ed25519'])}"])

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert found == []
    assert files[0].key_count == 0
    assert _by_sev(files[0].issues)["LOW"] == [
        f'line 1: bad key options (unknown key option "{marker}"); sshd rejects the whole line'
    ]


def test_authorized_keys_read_that_fails_partway_keeps_what_was_read(
    keys: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A file read a line at a time can fail after the first line, and the lines already read still count.

    Reading the file whole meant one failure or none; now that it is read a
    line at a time -- so that a huge file cannot exhaust memory -- a failing
    disk or a network filesystem going away partway through leaves the keys
    read up to that point reported, with the read failure alongside them.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    ak = _write_ak(alice, [pub(keys["ed25519"]), pub(keys["rsa4096"])])
    _patch_open(monkeypatch, ak, _FailsAfterTheFirstLine)

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].key_count == 1
    assert [f.line_number for f in found] == [1]
    assert _by_sev(files[0].issues)["LOW"] == ["could not read file: Input/output error"]


def test_authorized_keys_close_that_fails_is_reported_and_does_not_end_the_audit(
    keys: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Reading a file can report failure two ways, and closing it is the second one.

    A read that fails partway raises OSError from the read, which is caught;
    closing the file afterwards can raise OSError too, on the same failing
    disk or network filesystem. That one escaped audit_authorized_keys and
    ended the run for every account after this one. It gets the same answer as
    the first: a file-level finding, and the audit carries on to bob.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID, tmp_path / "home" / "bob")
    for u in (alice, bob):
        mkdir_clean(Path(u.pw_dir), tmp_path)
    ak = _write_ak(alice, [pub(keys["ed25519"])])
    _write_ak(bob, [pub(keys["rsa4096"])])
    _patch_open(monkeypatch, ak, _FailsOnClose)

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice, bob])

    by_user = {f.user: f for f in files}
    assert _by_sev(by_user["alice"].issues)["LOW"] == ["could not close file: Input/output error"]
    # Every line was read before the close failed, so the key on it still counts.
    assert by_user["alice"].key_count == 1
    # The account after alice was still audited, which is the whole point.
    assert by_user["bob"].issues == []
    assert [f.user for f in found] == ["alice", "bob"]


@pytest.mark.parametrize(
    ("stand_in", "expected"),
    [
        (_FailsAfterTheFirstLine, "could not read file: Input/output error"),
        (_FailsOnClose, "could not close file: Input/output error"),
    ],
)
def test_a_file_the_audit_could_not_read_to_the_end_is_not_reported_as_unchanged_for(
    keys: dict[str, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stand_in: Callable[[TextIO], Any],
    expected: str,
):
    """`not modified in N days` is for files the audit read, and a partial read is not one.

    The docs say a file the tool could not read is passed over, because the
    finding asks the operator to review every key in the file and the tool
    could not list them. A read that failed after the first line still counted
    that line, so the file picked the finding up anyway; so did a close that
    failed after every line was read. Both are now passed over, whichever way
    the failure was reported.

    The negative half is the same file read with nothing patched, which must
    still get the finding -- otherwise this test would pass against a version
    that never reports it at all.
    """
    alice = _account_with_authorized_keys(tmp_path, [pub(keys["ed25519"]), pub(keys["rsa4096"])], days_old=400)
    ak = Path(alice.pw_dir) / ".ssh" / "authorized_keys"
    assert [i.message for i in _one_file_finding(alice, unchanged_for_days=30).issues] == [
        "not modified in 30 days; review whether every key in it should still have access"
    ]

    _patch_open(monkeypatch, ak, stand_in)

    messages = [i.message for i in _one_file_finding(alice, unchanged_for_days=30).issues]
    assert messages == [expected]


def test_authorized_keys_last_line_without_a_line_ending_is_still_read(keys: dict[str, Path], tmp_path: Path):
    """A file that does not end in a newline still has its last line audited.

    sshd reads that line -- getline() hands back what it found before the end
    of the file -- and an editor leaving the final newline off is common
    enough. The read stops for want of more file rather than at the limit, so
    the line fits and is read whole.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    ssh_dir = Path(alice.pw_dir) / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    ak = ssh_dir / "authorized_keys"
    ak.write_text(f"{pub(keys['ed25519'])}\n{pub(keys['rsa4096'])}", encoding="utf-8", newline="")
    ak.chmod(0o600)

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].issues == []
    assert files[0].key_count == 2
    assert [f.line_number for f in found] == [1, 2]


def test_authorized_keys_with_crlf_line_endings_reads_like_any_other_file(keys: dict[str, Path], tmp_path: Path):
    """The carriage return of a CRLF file is dropped, so such a file reports exactly what sshd does with it.

    sshd keeps that carriage return -- its getline() stops at the newline --
    but it never reaches anything sshd acts on. On a line with a comment it
    lands inside the comment; on a line without one it lands inside the base64
    blob, which still decodes, because b64_pton() skips whitespace wherever it
    appears. Keeping it here would print an escaped control character at the
    end of every comment and turn every blank line in the file into a
    one-character line reported as bad key options.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    ssh_dir = Path(alice.pw_dir) / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    ak = ssh_dir / "authorized_keys"
    ak.write_bytes(f"# managed by hand\r\n\r\n{pub(keys['ed25519'])}\r\n".encode())
    ak.chmod(0o600)

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].issues == []
    assert files[0].key_count == 1
    assert [(f.line_number, f.comment) for f in found] == [(3, "ed@test")]


@pytest.mark.parametrize("ending", ["\n", "\r\n"], ids=["LF", "CRLF"])
def test_authorized_keys_line_longer_than_the_limit_is_reported_and_the_rest_is_still_audited(
    keys: dict[str, Path], tmp_path: Path, ending: str
):
    """Reading a line at a time bounds nothing on its own, because one line can be the whole file.

    sshd applies no per-line limit -- auth_check_authkeys_file()
    (auth2-pubkeyfile.c) reads the file with `getline()`, which grows its
    buffer to whatever the line needs -- so this limit is a deliberate
    divergence, for the reason set out on MAX_AUTHORIZED_KEYS_LINE. The line
    is reported rather than passed over in silence, because sshd does read it
    and may well authorise a key on it; and the file is wound on to the next
    line, so the keys after it are still audited, under the line numbers the
    operator's editor shows.

    Both line endings are tried, because what counts against the limit is
    what sits in front of the ending: a carriage return that is part of a
    CRLF ending is no more part of the line than the newline is.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    over = "ssh-ed25519 " + "A" * (audit.MAX_AUTHORIZED_KEYS_LINE + 1 - len("ssh-ed25519 "))
    assert len(over) == audit.MAX_AUTHORIZED_KEYS_LINE + 1
    _write_ak(alice, [pub(keys["ed25519"]), over, pub(keys["rsa4096"])], ending=ending)

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].key_count == 2
    # Line 3 is still line 3: the over-long line counts as the one line it is.
    assert [f.line_number for f in found] == [1, 3]
    assert _by_sev(files[0].issues)["LOW"] == [
        f"line 2: longer than {audit.MAX_AUTHORIZED_KEYS_LINE} characters, so it was not read; "
        "sshd has no such limit and does read it, so this line may hold a key that works"
    ]


@pytest.mark.parametrize("ending", ["\n", "\r\n"], ids=["LF", "CRLF"])
def test_authorized_keys_line_of_exactly_the_limit_is_read_as_an_ordinary_key(
    keys: dict[str, Path], tmp_path: Path, ending: str
):
    """The limit is the longest line still read, not the shortest one refused.

    One character more is the test above; this is the clean case, and it must
    leave no finding on the file at all. A real key line is padded out to the
    limit exactly with a long comment.

    A file with CRLF line endings is the case that used to fail. The file is
    opened with newline="\n", so such a line arrives with its carriage return
    still on it, and reading one character past the limit could not tell that
    carriage return from a line one character too long: a key line of exactly
    the limit was thrown away and reported as unread.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    base = f"{pub(keys['ed25519']).rsplit(' ', 1)[0]} "
    comment = "c" * (audit.MAX_AUTHORIZED_KEYS_LINE - len(base))
    at_the_limit = base + comment
    assert len(at_the_limit) == audit.MAX_AUTHORIZED_KEYS_LINE
    _write_ak(alice, [at_the_limit, pub(keys["rsa4096"])], ending=ending)

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].issues == []
    assert files[0].key_count == 2
    assert [f.line_number for f in found] == [1, 2]
    assert found[0].comment == comment


def test_authorized_keys_last_line_of_exactly_the_limit_with_a_stray_carriage_return_is_read(
    keys: dict[str, Path], tmp_path: Path
):
    """A carriage return with no newline after it is an ending too, and must not count against the limit.

    A file whose last line has no newline on it can still end in a carriage
    return -- a file with CRLF endings that was cut short, or one written by a
    program that put the two characters out separately. The reader is what
    decides whether that character is part of the line, and it has to decide
    it the way the caller does: the caller takes a trailing carriage return
    off every line, newline or no newline, so a last line of exactly the limit
    with one on the end fits once it is off. Counting it threw the line away
    and reported a key that works as unread.

    Nothing about sshd changes here: its getline() keeps the carriage return
    and it has no line limit at all.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    base = f"{pub(keys['ed25519']).rsplit(' ', 1)[0]} "
    comment = "c" * (audit.MAX_AUTHORIZED_KEYS_LINE - len(base))
    at_the_limit = base + comment
    assert len(at_the_limit) == audit.MAX_AUTHORIZED_KEYS_LINE
    ssh_dir = Path(alice.pw_dir) / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    ak = ssh_dir / "authorized_keys"
    # No newline anywhere: the carriage return is the last byte in the file.
    ak.write_text(at_the_limit + "\r", encoding="utf-8", newline="")
    ak.chmod(0o600)

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].issues == []
    assert files[0].key_count == 1
    assert [(f.line_number, f.comment) for f in found] == [(1, comment)]


def test_a_huge_one_line_authorized_keys_file_is_reported_not_read(tmp_path: Path):
    """Any account can end the root audit with a file that costs it a handful of disk blocks.

    `printf 'ssh-ed25519 AAAA' > ~/.ssh/authorized_keys; truncate -s 3G
    ~/.ssh/authorized_keys` leaves a file with no newline anywhere in it, so
    the whole three gigabytes is a single line. Reading the file a line at a
    time does not help: that bounds memory by the longest line, and here the
    longest line is the file. MemoryError is not an OSError, so nothing caught
    it and the audit of every remaining account died with it.

    The audit runs in a child process with a one-gigabyte cap on its address
    space, so the outcome is decided by the code rather than by how much
    memory the machine running the tests happens to have.
    """
    # Probe for sparse-file support on a throwaway file first. On a filesystem
    # without it, truncate() writes the bytes out, and finding that out with
    # the 3 GiB file would mean writing 3 GiB before deciding to skip.
    probe = tmp_path / "sparse_probe"
    probe.write_bytes(b"x")
    os.truncate(probe, 8 * 1024**2)
    if probe.stat().st_blocks * 512 > 1024**2:
        pytest.skip("this filesystem gave the sparse file real blocks, so the test would write 3 GiB")
    probe.unlink()

    home = tmp_path / "home"
    ssh_dir = mkdir_clean(home / ".ssh", tmp_path, mode=0o700)
    ak = ssh_dir / "authorized_keys"
    ak.write_bytes(b"ssh-ed25519 AAAA")
    os.truncate(ak, 3 * 1024**3)
    ak.chmod(0o600)

    script = tmp_path / "audit_one_authorized_keys.py"
    script.write_text(
        "import json, os, pwd, resource, sys\n"
        "resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))\n"
        "from audit_ssh_keys import audit\n"
        "user = pwd.struct_passwd(('tester', 'x', os.getuid(), os.getgid(), '', sys.argv[1], '/bin/sh'))\n"
        "_, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[user])\n"
        "print(json.dumps({'keys': len(found),\n"
        "                  'issues': [[i.severity, i.message] for f in files for i in f.issues]}))\n"
    )
    proc = subprocess.run(
        [sys.executable, str(script), str(home)],
        env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(Path(audit.__file__).parents[1])},
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )

    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {
        "keys": 0,
        "issues": [
            [
                "LOW",
                f"line 1: longer than {audit.MAX_AUTHORIZED_KEYS_LINE} characters, so it was not read; "
                "sshd has no such limit and does read it, so this line may hold a key that works",
            ]
        ],
    }


def _rewrite_ak_key_line(ak: Path, blob_byte: bytes = b"", comment: bytes = b"") -> None:
    """Rewrite the single key line in an authorized_keys file, splicing raw bytes into it.

    blob_byte goes into the middle of the key's base64; comment replaces the
    comment field. Written as bytes, because the point is bytes that are not
    valid UTF-8 and so cannot come from write_text.
    """
    type_name, blob, old_comment = ak.read_bytes().split(b" ", 2)
    cut = len(blob) // 2
    spliced = blob[:cut] + blob_byte + blob[cut:]
    ak.write_bytes(type_name + b" " + spliced + b" " + (comment or old_comment.strip() + b"\n"))


def test_authorized_keys_non_ascii_byte_in_a_key_blob_is_unparseable(keys: dict[str, Path], tmp_path: Path):
    """A byte that is not ASCII inside a key's base64 leaves a line sshd cannot read, and nor can this tool.

    The file is read with undecodable bytes replaced rather than dropped:
    dropping this one would join the base64 on either side of it back into a
    working key, reporting a line sshd throws away as a key that grants access.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _rewrite_ak_key_line(_write_ak(alice, [pub(keys["ed25519"])]), blob_byte=b"\xff")

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert found == []
    assert files[0].key_count == 0
    assert _by_sev(files[0].issues)["LOW"] == ["line 1: unparseable entry (ignored by sshd)"]


def test_authorized_keys_non_ascii_byte_in_a_comment_is_still_a_key(keys: dict[str, Path], tmp_path: Path):
    """A byte that is not ASCII in the comment field is shown as a replacement character, not dropped.

    sshd does not care what a comment holds, so the line is a working key and
    has to be counted as one -- only its comment looks different in the report.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _rewrite_ak_key_line(_write_ak(alice, [pub(keys["ed25519"])]), comment=b"wh\xffo@host\n")

    _, files, found, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert files[0].key_count == 1
    assert len(found) == 1
    assert found[0].key_type == "ED25519"
    assert found[0].comment == "wh\ufffdo@host"
    assert files[0].issues == []


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


def test_same_key_listed_twice_for_one_account_is_low_not_medium(keys: dict[str, Path], tmp_path: Path):
    """Two entries for one account grant no extra access, so they are noted at LOW, not MEDIUM."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    ak = _write_ak(alice, [pub(keys["ed25519"]), pub(keys["ed25519"])])

    _, _, found, dupes, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    assert [k.line_number for k in found] == [1, 2]
    fingerprint = found[0].fingerprint
    assert set(dupes) == {fingerprint}
    assert sorted(dupes[fingerprint]) == sorted([f"alice {ak}:1", f"alice {ak}:2"])
    for finding, other_line in ((found[0], 2), (found[1], 1)):
        sev = _by_sev(finding.issues)
        assert "MEDIUM" not in sev
        assert sev["LOW"] == [
            f"same key also listed for this account at: alice {ak}:{other_line}; removing one entry does not revoke it"
        ]


def test_same_key_in_both_of_one_account_s_files_is_low_not_medium(keys: dict[str, Path], tmp_path: Path):
    """authorized_keys and authorized_keys2 are two files but still one account, so still LOW."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    ak = _write_ak(alice, [pub(keys["ed25519"])])
    ak2 = ak.with_name("authorized_keys2")
    ak2.write_text(pub(keys["ed25519"]) + "\n")
    ak2.chmod(0o600)

    _, _, found, dupes, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    by_file = {k.file_path: k for k in found}
    assert set(by_file) == {str(ak), str(ak2)}
    fingerprint = found[0].fingerprint
    assert set(dupes) == {fingerprint}
    assert sorted(dupes[fingerprint]) == sorted([f"alice {ak}:1", f"alice {ak2}:1"])
    for path, other in ((ak, ak2), (ak2, ak)):
        sev = _by_sev(by_file[str(path)].issues)
        assert "MEDIUM" not in sev
        assert sev["LOW"] == [
            f"same key also listed for this account at: alice {other}:1; removing one entry does not revoke it"
        ]


def test_key_shared_between_accounts_is_medium_even_when_also_listed_twice(keys: dict[str, Path], tmp_path: Path):
    """A key authorised for two accounts is MEDIUM everywhere, with no second LOW alongside it."""
    root = make_user("root", 0, tmp_path / "root")
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    for u in (root, alice):
        mkdir_clean(Path(u.pw_dir), tmp_path)
    root_ak = _write_ak(root, [pub(keys["ed25519"]), pub(keys["ed25519"])])
    alice_ak = _write_ak(alice, [pub(keys["ed25519"])])

    _, _, found, dupes, _ = audit.audit_authorized_keys({}, 3072, users=[root, alice])

    assert len(found) == 3
    fingerprint = found[0].fingerprint
    assert sorted(dupes[fingerprint]) == sorted([f"root {root_ak}:1", f"root {root_ak}:2", f"alice {alice_ak}:1"])
    for finding in found:
        sev = _by_sev(finding.issues)
        assert len(sev["MEDIUM"]) == 1
        assert sev["MEDIUM"][0].startswith("same key also authorized at: ")
        assert not any("listed for this account" in m for m in sev.get("LOW", []))


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
        # {} means a successful sshd -T -C run for alice that sets nothing special,
        # so cfg_value falls back to the same default patterns as the global config.
        return {"authorizedkeysfile": [f"{custom}/%u"]} if user.pw_name == "bob" else {}

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
        # {} for alice is a successful sshd -T -C run that sets nothing special for her.
        return {"authorizedkeysfile": ["none"]} if user.pw_name == "bob" else {}

    _, files, ak, _, coverage = audit.audit_authorized_keys({}, 3072, users=[alice, bob], user_config=user_config)

    assert [(f.user, f.file_path) for f in files] == [("alice", str(alice_ak))]
    assert [k.user for k in ak] == ["alice"]
    assert len(coverage) == 1
    assert coverage[0].startswith("AuthorizedKeysFile is 'none' for bob (Match block)")


def test_authorized_keys_per_account_config_failure_is_reported_as_coverage(keys: dict[str, Path], tmp_path: Path):
    """When `sshd -T -C user=<account>` fails for one account, the report must say so, not go quiet about it.

    Falling back to the global AuthorizedKeysFile for that account is still
    correct behaviour -- but silently doing so while the report claims to be
    based on sshd -T would hide the fact that any Match block for that
    account was never applied.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID, tmp_path / "home" / "bob")
    for u in (alice, bob):
        mkdir_clean(Path(u.pw_dir), tmp_path)
    _write_ak(alice, [pub(keys["ed25519"])])
    bob_ak = _write_ak(bob, [pub(keys["rsa4096"])])

    def user_config(user: pwd.struct_passwd) -> dict[str, list[str]] | None:
        # None simulates `sshd -T -C user=bob` failing; alice's own run succeeds.
        return None if user.pw_name == "bob" else {"authorizedkeysfile": [".ssh/authorized_keys"]}

    _, files, ak, _, coverage = audit.audit_authorized_keys({}, 3072, users=[alice, bob], user_config=user_config)

    assert len(coverage) == 1
    assert coverage[0].startswith("could not read the effective sshd config for 1 account ")
    assert "sshd -T -C user=<name> failed for: bob" in coverage[0]
    assert not any("alice" in c for c in coverage)
    # The global AuthorizedKeysFile is still used for bob, so his file is scanned.
    bob_file = next((f for f in files if f.user == "bob"), None)
    assert bob_file is not None
    assert bob_file.file_path == str(bob_ak)
    assert {k.user for k in ak} == {"alice", "bob"}


def test_authorized_keys_several_per_account_config_failures_share_one_coverage_line(
    keys: dict[str, Path], tmp_path: Path
):
    """Every account whose own sshd -T -C run failed is named in one warning, not one warning each.

    A host where those runs fail for everybody would otherwise push the rest
    of the report out of sight behind hundreds of near-identical lines.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID, tmp_path / "home" / "bob")
    carol = make_user("carol", USER_UID, tmp_path / "home" / "carol")
    for u in (alice, bob, carol):
        mkdir_clean(Path(u.pw_dir), tmp_path)
        _write_ak(u, [pub(keys["ed25519"])])

    def user_config(user: pwd.struct_passwd) -> dict[str, list[str]] | None:
        # None simulates `sshd -T -C user=<name>` failing for both bob and carol.
        return {} if user.pw_name == "alice" else None

    _, _, _, _, coverage = audit.audit_authorized_keys({}, 3072, users=[alice, bob, carol], user_config=user_config)

    assert len(coverage) == 1
    assert coverage[0].startswith("could not read the effective sshd config for 2 accounts ")
    assert "sshd -T -C user=<name> failed for: bob, carol" in coverage[0]
    assert "alice" not in coverage[0]


def test_authorized_keys_no_user_config_callback_reports_no_per_account_failure(keys: dict[str, Path], tmp_path: Path):
    """With no user_config callback at all (the sshd -T fallback-parser case), nothing claims a per-account failure."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [pub(keys["ed25519"])])

    _, _, _, _, coverage = audit.audit_authorized_keys({}, 3072, users=[alice], user_config=None)

    assert not any("could not read the effective sshd config" in c for c in coverage)


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


def test_authorized_keys_none_pattern_is_case_insensitive(tmp_path: Path):
    """sshd compares AuthorizedKeysFile to 'none' with strcasecmp, so NONE must match too."""
    alice = make_user("alice", os.getuid(), tmp_path)
    patterns, files, ak, _, coverage = audit.audit_authorized_keys(
        {"authorizedkeysfile": ["NONE"]}, 3072, users=[alice]
    )
    assert patterns == [] and files == [] and ak == []
    assert coverage == ["AuthorizedKeysFile is 'none'; sshd reads no authorized_keys files."]


def test_authorized_keys_match_none_case_insensitive_skips_that_account_only(keys: dict[str, Path], tmp_path: Path):
    """A per-account AuthorizedKeysFile NONE (any case) from a Match block is honoured too."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID, tmp_path / "home" / "bob")
    for u in (alice, bob):
        mkdir_clean(Path(u.pw_dir), tmp_path)
    alice_ak = _write_ak(alice, [pub(keys["ed25519"])])
    _write_ak(bob, [pub(keys["rsa4096"])])

    def user_config(user: pwd.struct_passwd) -> dict[str, list[str]] | None:
        # {} for alice is a successful sshd -T -C run that sets nothing special for her.
        return {"authorizedkeysfile": ["NONE"]} if user.pw_name == "bob" else {}

    _, files, ak, _, coverage = audit.audit_authorized_keys({}, 3072, users=[alice, bob], user_config=user_config)

    assert [(f.user, f.file_path) for f in files] == [("alice", str(alice_ak))]
    assert [k.user for k in ak] == ["alice"]
    assert len(coverage) == 1
    assert coverage[0].startswith("AuthorizedKeysFile is 'none' for bob (Match block)")


def test_authorized_keys_none_entry_is_skipped_per_entry_not_whole_list(keys: dict[str, Path], tmp_path: Path):
    """sshd skips a 'none' AuthorizedKeysFile entry by itself, not only when the whole value is 'none'.

    "none .ssh/authorized_keys2" must scan authorized_keys2 and skip a file
    that happens to be named "none" -- and must not produce the "AuthorizedKeysFile
    is 'none'" coverage line, since some files are still being read. It gets the
    "mixes 'none' with other entries" warning instead, because OpenSSH's
    current development code refuses to start on that configuration, so a
    future upgrade may stop sshd from starting.
    """
    alice = make_user("alice", os.getuid(), tmp_path / "alice")
    mkdir_clean(Path(alice.pw_dir) / ".ssh", tmp_path)
    ak2 = Path(alice.pw_dir) / ".ssh" / "authorized_keys2"
    ak2.write_text(pub(keys["ed25519"]) + "\n")
    ak2.chmod(0o600)
    literal_none = Path(alice.pw_dir) / "none"
    literal_none.write_text(pub(keys["rsa4096"]) + "\n")
    literal_none.chmod(0o600)

    patterns, files, ak, _, coverage = audit.audit_authorized_keys(
        {"authorizedkeysfile": ["none .ssh/authorized_keys2"]}, 3072, users=[alice]
    )

    assert patterns == [".ssh/authorized_keys2"]
    assert [f.file_path for f in files] == [str(ak2)]
    assert [k.key_type for k in ak] == ["ED25519"]
    assert len(coverage) == 1
    assert coverage[0].startswith("AuthorizedKeysFile mixes 'none' with other entries (none .ssh/authorized_keys2)")
    assert not any("AuthorizedKeysFile is 'none'" in c for c in coverage)


def test_authorized_keys_mixed_none_warns_once_not_per_account(keys: dict[str, Path], tmp_path: Path):
    """A global value mixing 'none' with real paths is one warning, however many accounts there are.

    `sshd -T -C user=<name>` echoes the global AuthorizedKeysFile for every
    account, so a per-account check on its own would repeat the same warning
    once per account.
    """
    users = [make_user(name, USER_UID, tmp_path / "home" / name) for name in ("alice", "bob", "carol")]
    for user in users:
        mkdir_clean(Path(user.pw_dir), tmp_path)
        _write_ak(user, [pub(keys["ed25519"])])

    def user_config(user: pwd.struct_passwd) -> dict[str, list[str]] | None:
        return {"authorizedkeysfile": ["none .ssh/authorized_keys"]}

    _, files, ak, _, coverage = audit.audit_authorized_keys(
        {"authorizedkeysfile": ["none .ssh/authorized_keys"]}, 3072, users=users, user_config=user_config
    )

    assert len(coverage) == 1
    assert coverage[0] == (
        "AuthorizedKeysFile mixes 'none' with other entries (none .ssh/authorized_keys); "
        "released sshd versions skip just the 'none' entry and this audit does the same, "
        "but OpenSSH's current development code rejects the whole configuration, "
        "so a future upgrade may stop sshd from starting."
    )
    # The entries that are not 'none' are still scanned for every account.
    assert {f.user for f in files} == {"alice", "bob", "carol"}
    assert {k.user for k in ak} == {"alice", "bob", "carol"}


def test_authorized_keys_match_block_mixed_none_names_the_account(keys: dict[str, Path], tmp_path: Path):
    """A Match block that mixes 'none' in for one account is warned about for that account."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID, tmp_path / "home" / "bob")
    for user in (alice, bob):
        mkdir_clean(Path(user.pw_dir), tmp_path)
        _write_ak(user, [pub(keys["ed25519"])])

    def user_config(user: pwd.struct_passwd) -> dict[str, list[str]] | None:
        # {} for alice is a successful sshd -T -C run that sets nothing special for her.
        return {"authorizedkeysfile": ["none .ssh/authorized_keys"]} if user.pw_name == "bob" else {}

    _, files, ak, _, coverage = audit.audit_authorized_keys({}, 3072, users=[alice, bob], user_config=user_config)

    assert len(coverage) == 1
    assert coverage[0].startswith(
        "AuthorizedKeysFile mixes 'none' with other entries for bob (Match block) (none .ssh/authorized_keys)"
    )
    # bob's real entry is still scanned, and alice is not mentioned at all.
    assert {f.user for f in files} == {"alice", "bob"}
    assert {k.user for k in ak} == {"alice", "bob"}
    assert "alice" not in coverage[0]


def test_authorized_keys_unmixed_values_get_no_mixed_none_warning(keys: dict[str, Path], tmp_path: Path):
    """Neither a plain 'none' nor an ordinary value is a mixed value, so neither earns that warning."""
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    _write_ak(alice, [pub(keys["ed25519"])])

    for value in ("none", ".ssh/authorized_keys", ".ssh/authorized_keys .ssh/authorized_keys2"):
        _, _, _, _, coverage = audit.audit_authorized_keys({"authorizedkeysfile": [value]}, 3072, users=[alice])
        assert not any("mixes 'none'" in c for c in coverage), value


def test_authorized_keys_empty_pw_dir_does_not_read_cwd(
    keys: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """An empty pw_dir must mean the filesystem root, never the auditing process's own cwd."""
    assert not Path("/.ssh/authorized_keys").exists()  # keep the test honest
    nohome = pwd.struct_passwd(("nohome", "x", USER_UID, USER_UID, "nohome", "", "/bin/sh"))
    ssh_dir = mkdir_clean(tmp_path / ".ssh", tmp_path)
    ak = ssh_dir / "authorized_keys"
    ak.write_text(pub(keys["ed25519"]) + "\n")
    ak.chmod(0o600)
    monkeypatch.chdir(tmp_path)

    _, files, ak_findings, _, _ = audit.audit_authorized_keys({}, 3072, users=[nohome])

    assert [f for f in files if f.user == "nohome"] == []
    assert [k for k in ak_findings if k.user == "nohome"] == []


def test_authorized_keys_empty_file_still_reports_file_issues(tmp_path: Path):
    alice = make_user("alice", os.getuid(), tmp_path / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    ak = _write_ak(alice, ["# only a comment"], mode=0o666)
    _, files, findings, _, _ = audit.audit_authorized_keys({}, 3072, users=[alice])
    assert findings == []
    assert files[0].key_count == 0
    assert any(i.severity == "HIGH" and str(ak) in i.message for i in files[0].issues)


def test_read_private_key_bytes_stops_at_this_tools_own_size_limit(tmp_path: Path):
    """MAX_PRIVATE_KEY_FILE_SIZE is the largest file still read whole, not the smallest one refused.

    The limit is this tool's own and not ssh's: ssh reads a key file up to
    SSHBUF_SIZE_MAX (sshbuf.h), 128 MiB, and has done since OpenSSH 8.2.
    """
    at_the_limit = tmp_path / "at_the_limit"
    at_the_limit.write_bytes(b"x" * audit.MAX_PRIVATE_KEY_FILE_SIZE)
    one_byte_over = tmp_path / "one_byte_over"
    one_byte_over.write_bytes(b"x" * (audit.MAX_PRIVATE_KEY_FILE_SIZE + 1))

    assert audit._read_private_key_bytes(at_the_limit) == b"x" * audit.MAX_PRIVATE_KEY_FILE_SIZE
    assert audit._read_private_key_bytes(one_byte_over) is None


def test_an_oversized_key_file_answers_nothing_about_the_key(tmp_path: Path):
    """The cheap header check still says "private key", so every reader behind it has to hold the limit itself.

    Each of these took the whole file before, which is what a sparse file in
    somebody's ~/.ssh turned into a MemoryError.
    """
    over = tmp_path / "id_over"
    over.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + b"A" * audit.MAX_PRIVATE_KEY_FILE_SIZE)

    assert audit.looks_like_private_key(over) is True
    assert audit._private_key_format(over) is None
    assert audit.private_key_is_encrypted(over) is None
    assert audit.public_key_from_private(over) is None


# --- audit_private_keys --------------------------------------------------------


def test_a_huge_sparse_key_file_in_a_home_is_reported_not_read(tmp_path: Path):
    """Any account can end the audit with a file that costs it nothing.

    `printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\\n' > f; truncate -s 3G f`
    in its own ~/.ssh leaves a file that passes the 64-byte header check and
    then goes to three gigabytes while occupying one disk block. Every reader
    behind that check took the whole file, and MemoryError is not an OSError,
    so nothing caught it: one unprivileged account could stop the root audit.
    Stopping at MAX_PRIVATE_KEY_FILE_SIZE instead reports a key the audit
    could not fingerprint and could not tell the passphrase state of. ssh
    itself would load a file this size, so the finding says what this tool did
    not do, not what ssh cannot do.

    The audit runs in a child process with a one-gigabyte cap on its address
    space, so the outcome is decided by the code rather than by how much memory
    the machine running the tests happens to have.
    """
    # Probe for sparse-file support on a throwaway file first. On a filesystem
    # without it, truncate() writes the bytes out, and finding that out with
    # the 3 GiB file would mean writing 3 GiB before deciding to skip.
    probe = tmp_path / "sparse_probe"
    probe.write_bytes(b"x")
    os.truncate(probe, 8 * 1024**2)
    if probe.stat().st_blocks * 512 > 1024**2:
        pytest.skip("this filesystem gave the sparse file real blocks, so the test would write 3 GiB")
    probe.unlink()

    home = tmp_path / "home"
    ssh_dir = mkdir_clean(home / ".ssh", tmp_path, mode=0o700)
    huge = ssh_dir / "id_huge"
    huge.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
    os.truncate(huge, 3 * 1024**3)
    huge.chmod(0o600)

    script = tmp_path / "audit_one_home.py"
    script.write_text(
        "import json, os, pwd, resource, sys\n"
        "resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))\n"
        "from audit_ssh_keys import audit\n"
        "user = pwd.struct_passwd(('tester', 'x', os.getuid(), os.getgid(), '', sys.argv[1], '/bin/sh'))\n"
        "found = audit.audit_private_keys(3072, host_key_paths=set(), users=[user])\n"
        "print(json.dumps([{'type': f.key_type, 'encrypted': f.encrypted,\n"
        "                   'issues': [i.message for i in f.issues]} for f in found]))\n"
    )
    proc = subprocess.run(
        [sys.executable, str(script), str(home)],
        env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(Path(audit.__file__).parents[1])},
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )

    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == [
        {
            "type": "?",
            "encrypted": None,
            "issues": [
                "could not fingerprint private key; algorithm and size were not checked",
                "could not determine whether the key is passphrase-protected",
            ],
        }
    ]


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
    # An intact, unencrypted, current-format key at mode 0600: ssh can load it,
    # so the private-half check leaves it fingerprinted as usual.
    assert (root_key.key_type, root_key.bits) == ("ED25519", 256)
    assert root_key.fingerprint
    sev = _by_sev(root_key.issues)
    assert "private key has no passphrase" in sev["HIGH"]
    assert not any("could not fingerprint" in i.message for i in root_key.issues)


@needs_non_root
def test_private_keys_unstattable_home_is_skipped_not_a_crash(keys: dict[str, Path], tmp_path: Path):
    """An account whose home this tool cannot even stat must be skipped quietly, not crash the run.

    Regression test: os.stat() on a path below a 0o000 directory raises
    PermissionError on Python 3.10-3.12, and without the fix that propagated
    straight out of audit_private_keys. A second account with a normal,
    readable key is included to prove the rest of the run is unaffected.
    """
    alice = make_user("alice", USER_UID, tmp_path / "home" / "alice")
    bob = make_user("bob", USER_UID + 1, tmp_path / "home" / "bob")
    Path(alice.pw_dir).mkdir(parents=True, mode=0o700)
    b_ssh = mkdir_clean(Path(bob.pw_dir) / ".ssh", tmp_path)
    (b_ssh / "id_ed25519").write_bytes(keys["ed25519"].read_bytes())
    (b_ssh / "id_ed25519").chmod(0o600)
    Path(alice.pw_dir).chmod(0o000)

    try:
        findings = audit.audit_private_keys(3072, host_key_paths=set(), users=[alice, bob])
    finally:
        Path(alice.pw_dir).chmod(0o700)

    assert not any(f.user == "alice" for f in findings)
    assert any(f.user == "bob" for f in findings)


def test_private_keys_empty_pw_dir_does_not_read_cwd(
    keys: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """An empty pw_dir must mean the filesystem root, never the auditing process's own cwd.

    make_user stringifies its home argument, so an empty Path("") can't be
    built through it; build the passwd entry by hand, the way a real account
    with no home directory looks (see test_strictmodes_empty_pw_dir_does_not_stop_the_walk_early).
    """
    assert not Path("/.ssh").is_dir()  # keep the test honest: nothing here should be found for real
    nohome = pwd.struct_passwd(("nohome", "x", USER_UID, USER_UID, "nohome", "", "/bin/sh"))
    ssh_dir = mkdir_clean(tmp_path / ".ssh", tmp_path)
    key = ssh_dir / "id_ed25519"
    key.write_bytes(keys["ed25519"].read_bytes())
    key.chmod(0o600)
    monkeypatch.chdir(tmp_path)

    assert audit.audit_private_keys(3072, host_key_paths=set(), users=[nohome]) == []


def test_private_keys_pub_suffix_is_not_a_shortcut(keys: dict[str, Path], tmp_path: Path):
    """looks_like_private_key decides by content: a *.pub-named private key is audited, a genuine .pub file is not."""
    alice = make_user("alice", USER_UID, tmp_path / "alice")
    a_ssh = mkdir_clean(Path(alice.pw_dir) / ".ssh", tmp_path)
    backup = a_ssh / "backup.pub"
    backup.write_bytes(keys["ed25519"].read_bytes())
    backup.chmod(0o600)
    real_pub = a_ssh / "id_ed25519.pub"
    real_pub.write_text(pub(keys["ed25519"]) + "\n")

    findings = audit.audit_private_keys(3072, host_key_paths=set(), users=[alice])
    paths = {f.path for f in findings}

    assert str(backup) in paths
    assert str(real_pub) not in paths


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


def test_private_key_pem_stale_pub_is_flagged_and_the_private_key_wins(keys: dict[str, Path], tmp_path: Path):
    """End to end: a legacy PEM private key with a stale .pub is graded from the private key, not the .pub.

    Mirrors test_private_key_stale_pub_is_flagged_and_the_private_key_wins
    above, but for the PEM/PKCS#8 formats that have no embedded public half
    and so are fingerprinted through the symlink trick in
    _fingerprint_private_file_alone instead.
    """

    def write(a_ssh: Path) -> None:
        key = _pem_key(a_ssh / "id_rsa")
        audit.pub_sibling(key).write_text(pub(keys["ed25519"]) + "\n")
        key.chmod(0o600)

    finding = _one_private_key(tmp_path, write)
    assert finding.key_type == "RSA"
    lows = [i.message for i in finding.issues if i.severity == "LOW"]
    assert len([m for m in lows if m.startswith("id_rsa.pub does not match")]) == 1


def test_private_key_corrupt_openssh_body_with_unrelated_pub_is_unfingerprinted(keys: dict[str, Path], tmp_path: Path):
    """End to end: a corrupt current-format key is reported as unfingerprintable, not as its .pub neighbour.

    Same scenario as test_fingerprint_private_key_corrupt_openssh_body_is_not_reported_as_an_unrelated_pub,
    but through audit_private_keys, to prove the fix also holds for the finding
    that actually gets reported.
    """
    captured: dict[str, Path] = {}

    def write(a_ssh: Path) -> None:
        # Same truncated body as the "truncated" case in test_public_key_from_private_is_none_for_corrupt_bodies.
        payload = (
            _ssh_string(b"none")
            + _ssh_string(b"none")
            + _ssh_string(b"")
            + (1).to_bytes(4, "big")
            + (99).to_bytes(4, "big")
        )
        key = _openssh_key_file(a_ssh / "id_ed25519", payload)
        (a_ssh / "id_ed25519.pub").write_text(pub(keys["rsa2048"]) + "\n")  # a valid, but unrelated, key
        key.chmod(0o600)
        captured["path"] = key

    finding = _one_private_key(tmp_path, write)
    assert (finding.key_type, finding.fingerprint) == ("?", "")
    lows = [i.message for i in finding.issues if i.severity == "LOW"]
    assert "could not fingerprint private key; algorithm and size were not checked" in lows
    assert not any("does not match" in m for m in lows)
    assert audit.fingerprint_private_key(captured["path"]) == (None, None)


def test_private_key_ssh_cannot_load_is_reported_as_unfingerprintable(keys: dict[str, Path], tmp_path: Path):
    """End to end: a key whose private half ssh cannot load gets the LOW `could not fingerprint` finding.

    Same corruption as test_fingerprint_private_key_is_none_when_ssh_cannot_load_the_private_half,
    but through audit_private_keys, to prove it also reaches the finding that
    actually gets reported.
    """

    def write(a_ssh: Path) -> None:
        key = _corrupt_the_private_half(keys["ed25519"], a_ssh / "id_ed25519")
        audit.pub_sibling(key).write_text(pub(keys["ed25519"]) + "\n")

    finding = _one_private_key(tmp_path, write)
    assert (finding.key_type, finding.bits, finding.fingerprint) == ("?", 0, "")
    lows = [i.message for i in finding.issues if i.severity == "LOW"]
    assert "could not fingerprint private key; algorithm and size were not checked" in lows
    assert not any("does not match" in m for m in lows)


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


def test_private_key_reports_the_date_it_was_last_modified(keys: dict[str, Path], tmp_path: Path):
    def write(a_ssh: Path) -> None:
        key = a_ssh / "id_ed25519"
        key.write_bytes(keys["ed25519"].read_bytes())
        key.chmod(0o600)
        _set_mtime(key)

    assert _one_private_key(tmp_path, write).last_modified == KNOWN_DATE


def test_private_key_that_cannot_be_stat_d_is_still_audited_without_a_date(
    keys: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The directory listing already found a regular file, so a stat failure here is a race, not a layout problem.

    The key is still reported -- with no date, rather than not at all.
    """
    key_name = "id_ed25519"
    real_stat = audit._stat_if_present

    def stat_except_the_key(path: Path) -> os.stat_result | None:
        if path.name == key_name:
            raise OSError("vanished")
        return real_stat(path)

    def write(a_ssh: Path) -> None:
        key = a_ssh / key_name
        key.write_bytes(keys["ed25519"].read_bytes())
        key.chmod(0o600)
        monkeypatch.setattr(audit, "_stat_if_present", stat_except_the_key)

    finding = _one_private_key(tmp_path, write)
    assert finding.last_modified is None
    assert finding.key_type == "ED25519"


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
    monkeypatch.setattr(audit, "_find_sshd", lambda: None)
    monkeypatch.setattr(audit, "DEFAULT_HOST_KEYS", [str(tmp_path / "nokey")])
    monkeypatch.setattr(audit.pwd, "getpwall", lambda: [])

    report = audit.run_audit(3072, do_host=True, do_authorized=True, do_private=True)
    # No HostKey is configured and the (monkeypatched) default doesn't exist,
    # so sshd has no host key at all -- that is itself a finding, not silence.
    assert [(f.path, f.key_type) for f in report.host_keys] == [("(none)", "?")]
    assert report.authorized_keys == [] and report.private_keys == []
    assert any("AuthorizedKeysFile is 'none'" in w for w in report.coverage_warnings)

    audit.print_report(report)
    out = capsys.readouterr().out
    assert "Coverage warnings" in out
    assert out.strip().endswith("Totals: LOW: 1")

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
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "audit-ssh-keys unknown"


# --- verbose report ------------------------------------------------------------


def _report_with_one_clean_and_one_flagged_key(keys: dict[str, Path], tmp_path: Path) -> audit.Report:
    alice = make_user("alice", USER_UID, tmp_path / "alice")
    mkdir_clean(Path(alice.pw_dir), tmp_path)
    # A known date on the authorized_keys file, so the file header and every
    # key line taken from it can be checked against a literal date.
    _set_mtime(_write_ak(alice, [pub(keys["rsa4096"]), pub(keys["rsa2048"])]))
    patterns, files, ak, dupes, _ = audit.audit_authorized_keys({}, 3072, users=[alice])

    # The flagged entries carry a date and the clean ones do not, so one report
    # shows both what a line looks like with a date and what it looks like
    # without one.
    host_keys = [
        audit.HostKeyFinding("/etc/ssh/ssh_host_ed25519_key_clean", "ED25519", 256, "SHA256:cleanhostkey"),
        audit.HostKeyFinding(
            "/etc/ssh/ssh_host_rsa_key_flagged",
            "RSA",
            2048,
            "SHA256:flaggedhostkey",
            issues=[audit.Issue("LOW", "example host key finding")],
            last_modified=KNOWN_DATE,
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
            last_modified=KNOWN_DATE,
        ),
    ]

    # A file-level finding, so the default layout prints the per-file header for
    # it, and a server-configuration finding, so that section is printed too.
    files[0].issues.append(audit.Issue("HIGH", "example file finding"))

    return audit.Report(
        config_source="sshd -T",
        effective_authorized_keys_file=patterns,
        coverage_warnings=[],
        server_config_issues=[audit.Issue("MEDIUM", "example server configuration finding")],
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
    # A section of its own for the server configuration, and the per-file header
    # above a file-level finding, which is the only place a file's own findings
    # are shown in this layout.
    assert "=== Server configuration ===" in out
    assert "[MEDIUM] example server configuration finding" in out
    lines = out.splitlines()
    i_file = next(
        i
        for i, ln in enumerate(lines)
        if ln.startswith("alice: ") and ln.endswith(f"key(s), last modified {KNOWN_DATE})")
    )
    assert lines[i_file + 1] == "  [HIGH] example file finding"


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


@pytest.mark.parametrize("verbose", [False, True])
def test_report_shows_the_last_modified_date_on_every_file_heading(keys, tmp_path, capsys, verbose: bool):
    report = _report_with_one_clean_and_one_flagged_key(keys, tmp_path)
    audit.print_report(report, verbose=verbose)
    lines = capsys.readouterr().out.splitlines()
    ak_path = report.authorized_key_files[0].file_path

    assert f"/etc/ssh/ssh_host_rsa_key_flagged (last modified {KNOWN_DATE})" in lines
    assert f"alice: {ak_path} (2 key(s), last modified {KNOWN_DATE})" in lines
    assert f"alice: /home/alice/.ssh/id_rsa_flagged (last modified {KNOWN_DATE})" in lines
    if not verbose:
        # Only the default layout names the file on the key line; the verbose
        # layout groups keys under the file header, whose date is checked above.
        assert f"alice: {ak_path}:2 (last modified {KNOWN_DATE})" in lines


def test_report_omits_the_date_when_there_is_none_to_report(capsys):
    """A file with no date prints exactly the line it printed before dates were reported at all.

    Every entry here has a finding, so the default layout prints all four of
    the line shapes that can carry a date.
    """
    file_path = "/home/alice/.ssh/authorized_keys"
    example = [audit.Issue("LOW", "example finding")]
    report = audit.Report(
        config_source="sshd -T",
        effective_authorized_keys_file=[".ssh/authorized_keys"],
        coverage_warnings=[],
        server_config_issues=[],
        host_keys=[
            audit.HostKeyFinding("/etc/ssh/ssh_host_ed25519_key", "ED25519", 256, "SHA256:hostkey", issues=example)
        ],
        authorized_key_files=[audit.FileFinding(user="alice", file_path=file_path, key_count=1, issues=example)],
        authorized_keys=[
            audit.AuthorizedKeyFinding(
                user="alice",
                file_path=file_path,
                line_number=1,
                key_type="ED25519",
                bits=256,
                fingerprint="SHA256:authkey",
                comment="alice@test",
                options=[],
                issues=example,
            )
        ],
        duplicate_authorized_keys={},
        private_keys=[
            audit.PrivateKeyFinding(
                "alice", "/home/alice/.ssh/id_ed25519", "ED25519", 256, "SHA256:priv", True, issues=example
            )
        ],
    )

    audit.print_report(report)
    out = capsys.readouterr().out
    lines = out.splitlines()

    assert "last modified" not in out
    assert "/etc/ssh/ssh_host_ed25519_key" in lines
    assert f"alice: {file_path} (1 key(s))" in lines
    assert f"alice: {file_path}:1" in lines
    assert "alice: /home/alice/.ssh/id_ed25519" in lines


def test_json_carries_the_last_modified_dates_and_nulls(keys, tmp_path):
    """asdict() is what --json emits, so the new fields have to survive it -- including their null state."""
    report = _report_with_one_clean_and_one_flagged_key(keys, tmp_path)
    payload = json.loads(json.dumps(asdict(report)))

    assert [h["last_modified"] for h in payload["host_keys"]] == [None, KNOWN_DATE]
    assert [p["last_modified"] for p in payload["private_keys"]] == [None, KNOWN_DATE]
    assert [f["last_modified"] for f in payload["authorized_key_files"]] == [KNOWN_DATE]
    assert [k["file_last_modified"] for k in payload["authorized_keys"]] == [KNOWN_DATE, KNOWN_DATE]
    assert '"last_modified": null' in json.dumps(payload)


def test_default_report_says_no_findings_in_every_section_that_has_none(capsys):
    """A section whose keys are all clean has to say so rather than print a bare header.

    The default layout lists only the keys with findings, so on a host where
    everything is clean all three sections would otherwise be a header with
    nothing under it -- indistinguishable from a section the tool failed to
    fill in.
    """
    file_path = "/home/alice/.ssh/authorized_keys"
    report = audit.Report(
        config_source="sshd -T",
        effective_authorized_keys_file=[".ssh/authorized_keys"],
        coverage_warnings=[],
        server_config_issues=[],
        host_keys=[audit.HostKeyFinding("/etc/ssh/ssh_host_ed25519_key", "ED25519", 256, "SHA256:cleanhostkey")],
        authorized_key_files=[audit.FileFinding(user="alice", file_path=file_path, key_count=1)],
        authorized_keys=[
            audit.AuthorizedKeyFinding(
                user="alice",
                file_path=file_path,
                line_number=1,
                key_type="ED25519",
                bits=256,
                fingerprint="SHA256:cleanauthkey",
                comment="alice@test",
                options=[],
            )
        ],
        duplicate_authorized_keys={},
        private_keys=[
            audit.PrivateKeyFinding("alice", "/home/alice/.ssh/id_ed25519", "ED25519", 256, "SHA256:cleanpriv", True)
        ],
    )

    audit.print_report(report)
    out = capsys.readouterr().out

    assert out.count("  no findings") == 3  # host keys, authorized_keys, private keys
    assert "=== Server configuration ===" not in out  # no findings there means no section at all
    assert "alice@test" not in out  # a clean key is not listed in this layout
    assert out.strip().endswith("Totals: no issues")


def test_verbose_report_groups_shared_file_by_account_not_just_by_path(capsys):
    """A shared absolute AuthorizedKeysFile gets a FileFinding per account; keys must not bleed across them.

    Grouping keys by file_path alone would put both accounts' keys under both
    accounts' headers, since a shared file has the same file_path for every
    account that reads it.
    """
    shared_path = "/etc/ssh/authorized_keys"
    files = [
        audit.FileFinding(user="root", file_path=shared_path, key_count=1),
        audit.FileFinding(user="alice", file_path=shared_path, key_count=1),
    ]
    keys = [
        audit.AuthorizedKeyFinding(
            user="root",
            file_path=shared_path,
            line_number=1,
            key_type="ED25519",
            bits=256,
            fingerprint="SHA256:root",
            comment="root-only@test",
            options=[],
        ),
        audit.AuthorizedKeyFinding(
            user="alice",
            file_path=shared_path,
            line_number=1,
            key_type="ED25519",
            bits=256,
            fingerprint="SHA256:alice",
            comment="alice-only@test",
            options=[],
        ),
    ]
    report = audit.Report(
        config_source="sshd -T",
        effective_authorized_keys_file=[shared_path],
        coverage_warnings=[],
        server_config_issues=[],
        host_keys=[],
        authorized_key_files=files,
        authorized_keys=keys,
        duplicate_authorized_keys={},
        private_keys=[],
    )

    audit.print_report(report, verbose=True)
    out = capsys.readouterr().out
    lines = out.splitlines()

    assert out.count("root-only@test") == 1
    assert out.count("alice-only@test") == 1

    i_root_header = next(i for i, ln in enumerate(lines) if ln.startswith("root: "))
    i_alice_header = next(i for i, ln in enumerate(lines) if ln.startswith("alice: "))
    i_root_comment = next(i for i, ln in enumerate(lines) if "root-only@test" in ln)
    i_alice_comment = next(i for i, ln in enumerate(lines) if "alice-only@test" in ln)

    if i_root_header < i_alice_header:
        assert i_root_header < i_root_comment < i_alice_header < i_alice_comment
    else:
        assert i_alice_header < i_alice_comment < i_root_header < i_root_comment


def test_cli_verbose_flag(keys, tmp_path, monkeypatch, capsys):
    report = _report_with_one_clean_and_one_flagged_key(keys, tmp_path)
    monkeypatch.setattr(audit, "run_audit", lambda *_a, **_k: report)
    audit.main(["--verbose"])
    assert "rsa4096@test" in capsys.readouterr().out
    audit.main([])
    assert "rsa4096@test" not in capsys.readouterr().out


def _record_threshold_kwargs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, dict[str, int | None]]:
    """Stand in for the two audit functions that take thresholds and record what they were given.

    The rest of the run is kept off the real system the same way
    test_run_audit_and_report_smoke does it.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text("PasswordAuthentication no\n")
    monkeypatch.setattr(audit, "SSHD_CONFIG", cfg)
    monkeypatch.setattr(audit, "_find_sshd", lambda: None)
    monkeypatch.setattr(audit.pwd, "getpwall", lambda: [])
    recorded: dict[str, dict[str, int | None]] = {}

    def fake_authorized_keys(config, min_rsa_bits, users=None, user_config=None, **kwargs):
        recorded["authorized_keys"] = kwargs
        return [], [], [], {}, []

    def fake_host_keys(config, min_rsa_bits, **kwargs):
        recorded["host_keys"] = kwargs
        return []

    monkeypatch.setattr(audit, "audit_authorized_keys", fake_authorized_keys)
    monkeypatch.setattr(audit, "audit_host_keys", fake_host_keys)
    return recorded


def test_cli_hands_each_threshold_to_the_audit_it_belongs_to(tmp_path, monkeypatch, capsys):
    """Each option reaches one audit function, under the name that function expects."""
    recorded = _record_threshold_kwargs(monkeypatch, tmp_path)

    audit.main(
        [
            "--skip-private",
            "--authorized-keys-unchanged-for",
            "30",
            "--authorized-keys-changed-within",
            "7",
            "--host-keys-changed-within",
            "3",
        ]
    )
    capsys.readouterr()

    assert recorded["authorized_keys"] == {"unchanged_for_days": 30, "changed_within_days": 7}
    assert recorded["host_keys"] == {"changed_within_days": 3}


def test_cli_leaves_every_threshold_off_when_no_option_is_given(tmp_path, monkeypatch, capsys):
    """The other half of the claim above: nothing is switched on by default."""
    recorded = _record_threshold_kwargs(monkeypatch, tmp_path)

    audit.main(["--skip-private"])
    capsys.readouterr()

    assert recorded["authorized_keys"] == {"unchanged_for_days": None, "changed_within_days": None}
    assert recorded["host_keys"] == {"changed_within_days": None}


@pytest.mark.parametrize(
    "option",
    ["--authorized-keys-unchanged-for", "--authorized-keys-changed-within", "--host-keys-changed-within"],
)
@pytest.mark.parametrize("value", ["0", "-1"])
def test_cli_rejects_a_window_shorter_than_a_day(option: str, value: str, capsys):
    """Zero days is a window nothing can fall inside, and a negative one means nothing at all."""
    with pytest.raises(SystemExit) as exit_info:
        audit.main([option, value])

    assert exit_info.value.code == 2
    assert f"{option}: DAYS must be 1 or more, not {value}" in capsys.readouterr().err


@pytest.mark.parametrize(
    "option",
    ["--authorized-keys-unchanged-for", "--authorized-keys-changed-within", "--host-keys-changed-within"],
)
def test_cli_rejects_a_window_with_more_digits_than_int_will_parse(option: str, monkeypatch, capsys):
    """int() refuses a string above 4300 digits, and that has to be a usage error, not a traceback.

    The digit limit arrived in Python 3.10.7; on an interpreter without it the
    value parses, so the audit is stubbed out to make sure this test can never
    fall through into a real audit of the host it runs on.
    """
    monkeypatch.setattr(audit, "run_audit", lambda *_a, **_k: pytest.fail("the option was accepted"))
    with pytest.raises(SystemExit) as exit_info:
        audit.main([option, "9" * 5000])

    assert exit_info.value.code == 2
    assert "invalid int value" in capsys.readouterr().err


# --- escaping control characters in the text report ----------------------------

_ANSI_COMMENT = "\x1b[31mred\x1b[0m"
_OSC_OPTION = 'command="\x1b]0;evil\x07"'


def test_printable_escapes_only_what_a_terminal_would_act_on():
    assert audit._printable("plain text") == "plain text"
    assert audit._printable("Müller") == "Müller"  # ordinary non-ASCII text is text, not a control sequence
    assert audit._printable("a\nb") == "a\nb"  # the report's own line breaks have to survive
    assert audit._printable(_ANSI_COMMENT) == "\\x1b[31mred\\x1b[0m"
    assert audit._printable("bell\x07") == "bell\\x07"
    assert audit._printable("tab\there") == "tab\\x09here"  # a tab would move the cursor across the layout
    assert audit._printable("\x7f\x85") == "\\x7f\\x85"  # DEL, and a control character above ASCII
    assert audit._printable("zero​width") == "zero\\u200bwidth"  # invisible as printed, so shown as an escape
    # Line and paragraph separators are not control characters by category, but
    # some terminals and pagers break a line on them, so they are escaped too.
    assert audit._printable("a\u2028b\u2029c") == "a\\u2028b\\u2029c"
    # A tag character: a format character above U+FFFF, so it takes the \U form.
    assert audit._printable("tag\U000e0020here") == "tag\\U000e0020here"
    # A lone surrogate cannot even be encoded for the terminal, so it is escaped.
    assert audit._printable("half\ud800pair") == "half\\ud800pair"


def test_printable_leaves_private_use_and_unassigned_code_points_alone():
    """Neither is something a terminal acts on, and escaping the unassigned ones is not stable.

    Which code points are unassigned comes from the Unicode tables built into
    the interpreter, so a new emoji is unassigned on one Python version and
    assigned on the next. Escaping by that would make the same key comment print
    differently on two hosts, for a character no terminal treats specially
    either way.
    """
    assert audit._printable("\U0001fae9") == "\U0001fae9"  # unassigned in Python 3.11, an emoji from 3.13 on
    assert audit._printable("puahere") == "puahere"  # private use, inside U+FFFF
    assert audit._printable("pua\U000f0000here") == "pua\U000f0000here"  # private use, above U+FFFF


def _report_with_terminal_escapes_in_account_controlled_text() -> audit.Report:
    """A report whose key comment, key options and coverage warning all hold escape sequences.

    Every one of them is text an ordinary account writes into its own
    authorized_keys file, or a message of this tool's own that quotes it. The
    second key's comment is ordinary non-ASCII text, which must come through
    unchanged.
    """
    file_path = "/home/alice/.ssh/authorized_keys"
    ak = [
        audit.AuthorizedKeyFinding(
            user="alice",
            file_path=file_path,
            line_number=1,
            key_type="ED25519",
            bits=256,
            fingerprint="SHA256:withescapes",
            comment=_ANSI_COMMENT,
            options=[_OSC_OPTION],
            issues=[audit.Issue("LOW", f"line 1: example finding quoting the comment {_ANSI_COMMENT}")],
        ),
        audit.AuthorizedKeyFinding(
            user="alice",
            file_path=file_path,
            line_number=2,
            key_type="ED25519",
            bits=256,
            fingerprint="SHA256:plaintext",
            comment="Müller",
            options=[],
            issues=[audit.Issue("LOW", "line 2: example finding")],
        ),
    ]
    return audit.Report(
        config_source="sshd -T",
        effective_authorized_keys_file=[".ssh/authorized_keys"],
        coverage_warnings=["AuthorizedKeysCommand is set: \x1b[2Jkeys served by a command are not audited"],
        server_config_issues=[],
        host_keys=[],
        authorized_key_files=[audit.FileFinding(user="alice", file_path=file_path, key_count=2)],
        authorized_keys=ak,
        duplicate_authorized_keys={},
        private_keys=[],
    )


@pytest.mark.parametrize("verbose", [False, True], ids=["default report", "verbose report"])
def test_text_report_escapes_control_characters_from_an_authorized_keys_file(verbose: bool, capsys):
    """An escape sequence in a key comment or option must not reach the operator's terminal.

    A comment is whatever the account that owns the file put there, so it can
    hold an ANSI sequence that recolours the report, erases a line the operator
    has already read, or (as an OSC sequence) rewrites the window title. The
    report shows the escapes instead of acting on them, in both the default and
    the verbose layout, and in this tool's own messages that quote the comment.
    """
    audit.print_report(_report_with_terminal_escapes_in_account_controlled_text(), verbose=verbose)
    out = capsys.readouterr().out

    assert "\x1b" not in out and "\x07" not in out
    assert out.count("\\x1b[31mred\\x1b[0m") == 2  # the comment itself, and the finding quoting it
    assert 'command="\\x1b]0;evil\\x07"' in out
    assert "\\x1b[2J" in out  # the coverage warning
    assert "Müller" in out  # ordinary non-ASCII text is printed as it stands


def test_text_report_survives_an_ascii_stdout(monkeypatch: pytest.MonkeyPatch):
    """A non-ASCII key comment must not abort the report when stdout cannot encode it.

    Under an ASCII locale -- LC_ALL=C with Python's UTF-8 coercion turned off --
    stdout is an ASCII stream, and a key comment holds whatever the account that
    owns the file put there. print() would raise UnicodeEncodeError on the first
    non-ASCII character and abandon the report part way through, which is worse
    than an unreadable character: the operator loses the findings below it. The
    report asks stdout to write what it cannot encode as a backslash escape
    instead, so the whole report comes out and the byte is still shown.
    """
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="ascii", newline="\n"))

    audit.print_report(_report_with_terminal_escapes_in_account_controlled_text())
    sys.stdout.flush()

    written = raw.getvalue()
    assert b"M\\xfcller" in written  # the u-umlaut as its backslash escape
    assert written.strip().endswith(b"Totals: LOW: 2")  # the report ran to the end
