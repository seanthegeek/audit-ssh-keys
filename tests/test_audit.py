"""Tests for permission checks and the host-key, authorized_keys, and private-key sections.

These generate real keys with ssh-keygen and lay out fake home directories
under tmp_path, then feed fake passwd entries to the audit functions.
"""

from __future__ import annotations

import os
import pwd
from pathlib import Path

import pytest

from audit_ssh_keys import audit
from tests.conftest import USER_UID, make_user, needs_root, needs_ssh_keygen, pub

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


def test_strictmodes_missing_file_is_low(tmp_path: Path):
    alice = make_user("alice", os.getuid(), tmp_path)
    issues = audit.check_strictmodes_path(tmp_path / ".ssh" / "authorized_keys", alice)
    assert any(i.severity == "LOW" and "could not stat" in i.message for i in issues)


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
    findings = audit.audit_host_keys(config, min_rsa_bits=3072)
    by_path = {f.path: f for f in findings}

    assert by_path[str(rsa)].key_type == "RSA" and by_path[str(rsa)].bits == 2048
    sev = _by_sev(by_path[str(rsa)].issues)
    assert any("below policy minimum" in m for m in sev["MEDIUM"])
    assert any("world-accessible" in m and "sshd refuses" in m for m in sev["CRITICAL"])

    assert by_path[str(ed)].key_type == "ED25519"
    assert by_path[str(ed)].issues == []

    assert [i.message for i in by_path[str(tmp_path / "missing")].issues] == ["configured HostKey does not exist"]
    assert "(none)" not in by_path  # an Ed25519 key is present, so no "missing Ed25519" entry


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
    assert findings[0].fingerprint  # fingerprinted via the .pub sibling
    assert any(i.severity == "LOW" and "passphrase" in i.message for i in findings[0].issues)


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
    Path(alice.pw_dir).mkdir()
    keydir = tmp_path / "etc" / "ssh" / "authorized_keys"
    keydir.mkdir(parents=True)
    (keydir / "alice").write_text(pub(keys["ed25519"]) + "\n")
    # Same path listed twice must only be scanned once.
    config = {"authorizedkeysfile": [f"{keydir}/%u {keydir}/%u"]}
    _, files, ak, dupes, _ = audit.audit_authorized_keys(config, 3072, users=[alice])
    assert [f.file_path for f in files] == [str(keydir / "alice")]
    assert len(ak) == 1
    assert dupes == {}


def test_authorized_keys_none_pattern(tmp_path: Path):
    alice = make_user("alice", os.getuid(), tmp_path)
    patterns, files, ak, _, coverage = audit.audit_authorized_keys(
        {"authorizedkeysfile": ["none"]}, 3072, users=[alice]
    )
    assert patterns == [] and files == [] and ak == []
    assert coverage and "none" in coverage[0]


def test_authorized_keys_empty_file_still_reports_file_issues(tmp_path: Path):
    alice = make_user("alice", os.getuid(), tmp_path / "alice")
    Path(alice.pw_dir).mkdir()
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
        (Path(u.pw_dir) / ".ssh").mkdir(parents=True)

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
    assert enc.fingerprint and enc.key_type == "ED25519"  # via .pub sibling
    assert enc.issues == []

    old = by_path[str(a_ssh / "id_rsa_old")]
    assert old.encrypted is False
    assert (old.key_type, old.bits) == ("RSA", 1024)  # fingerprinted from the private key itself
    sev = _by_sev(old.issues)
    assert len(sev["CRITICAL"]) == 2  # 1024-bit + world-accessible
    assert sev["MEDIUM"] == ["private key has no passphrase"]

    root_key = by_path[str(r_ssh / "id_ed25519")]
    sev = _by_sev(root_key.issues)
    assert "private key has no passphrase" in sev["HIGH"]


def test_private_keys_skips_symlinks_and_missing_dirs(keys: dict[str, Path], tmp_path: Path):
    alice = make_user("alice", os.getuid(), tmp_path / "alice")
    bob = make_user("bob", os.getuid(), tmp_path / "bob")  # no .ssh at all
    a_ssh = Path(alice.pw_dir) / ".ssh"
    a_ssh.mkdir(parents=True)
    (a_ssh / "link").symlink_to(keys["ed25519"])
    assert audit.audit_private_keys(3072, host_key_paths=set(), users=[alice, bob]) == []


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


# --- verbose report ------------------------------------------------------------


def _report_with_one_clean_and_one_flagged_key(keys: dict[str, Path], tmp_path: Path) -> audit.Report:
    alice = make_user("alice", USER_UID, tmp_path / "alice")
    Path(alice.pw_dir).mkdir()
    _write_ak(alice, [pub(keys["rsa4096"]), pub(keys["rsa2048"])])
    patterns, files, ak, dupes, _ = audit.audit_authorized_keys({}, 3072, users=[alice])
    return audit.Report(
        config_source="sshd -T",
        effective_authorized_keys_file=patterns,
        coverage_warnings=[],
        server_config_issues=[],
        host_keys=[],
        authorized_key_files=files,
        authorized_keys=ak,
        duplicate_authorized_keys=dupes,
        private_keys=[],
    )


def test_default_report_lists_only_keys_with_findings(keys, tmp_path, capsys):
    report = _report_with_one_clean_and_one_flagged_key(keys, tmp_path)
    audit.print_report(report)
    out = capsys.readouterr().out
    assert "rsa2048@test" in out
    assert "rsa4096@test" not in out
    assert "  ok" not in out


def test_verbose_report_lists_every_key_grouped_by_file(keys, tmp_path, capsys):
    report = _report_with_one_clean_and_one_flagged_key(keys, tmp_path)
    audit.print_report(report, verbose=True)
    out = capsys.readouterr().out
    assert "rsa4096@test" in out and "rsa2048@test" in out
    # Grouped under the file header, in line order, clean key marked ok.
    lines = out.splitlines()
    i_file = next(i for i, ln in enumerate(lines) if ln.startswith("alice: ") and "authorized_keys" in ln)
    i_1 = next(i for i, ln in enumerate(lines) if ln.startswith("  line 1: RSA 4096-bit"))
    i_2 = next(i for i, ln in enumerate(lines) if ln.startswith("  line 2: RSA 2048-bit"))
    assert i_file < i_1 < i_2
    assert lines[i_1 + 1] == "    ok"
    assert lines[i_2 + 1].startswith("    [MEDIUM]")


def test_cli_verbose_flag(keys, tmp_path, monkeypatch, capsys):
    report = _report_with_one_clean_and_one_flagged_key(keys, tmp_path)
    monkeypatch.setattr(audit, "run_audit", lambda *_a, **_k: report)
    audit.main(["--verbose"])
    assert "rsa4096@test" in capsys.readouterr().out
    audit.main([])
    assert "rsa4096@test" not in capsys.readouterr().out
