"""Tests for reading sshd configuration and grading server settings."""

from __future__ import annotations

import stat
from pathlib import Path

from audit_ssh_keys import audit


def _fake_sshd(tmp_path: Path, stdout: str = "", stderr: str = "", rc: int = 0) -> str:
    """A shell script standing in for `sshd -T`."""
    script = tmp_path / "sshd"
    script.write_text(f"#!/bin/sh\nprintf '%s' '{stdout}'\nprintf '%s' '{stderr}' >&2\nexit {rc}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


# --- read_effective_sshd_config: sshd -T path -------------------------------


def test_sshd_t_output_is_parsed_with_repeating_hostkey(tmp_path: Path):
    out = "hostkey /etc/ssh/a\nhostkey /etc/ssh/b\nauthorizedkeysfile .ssh/authorized_keys\nstrictmodes yes\n"
    config, source, err = audit.read_effective_sshd_config(sshd_bin=_fake_sshd(tmp_path, stdout=out))
    assert source == "sshd -T"
    assert err == ""
    assert config["hostkey"] == ["/etc/ssh/a", "/etc/ssh/b"]
    assert config["authorizedkeysfile"] == [".ssh/authorized_keys"]


def test_sshd_t_failure_falls_back_and_reports_stderr(tmp_path: Path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text("AuthorizedKeysFile /custom/%u\n")
    err_text = "@@@ banner\nUnable to load host key: /etc/ssh/x\nMissing privilege separation directory: /run/sshd\n"
    config, source, err = audit.read_effective_sshd_config(
        sshd_bin=_fake_sshd(tmp_path, stderr=err_text, rc=255), config_paths=[cfg]
    )
    assert source.startswith("parsed sshd_config")
    assert "Unable to load host key: /etc/ssh/x" in err
    assert "@@@" not in err  # banner lines are dropped
    assert config["authorizedkeysfile"] == ["/custom/%u"]


def test_no_sshd_binary_reports_missing(tmp_path: Path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text("")
    config, source, err = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert source.startswith("parsed sshd_config")
    assert config == {}
    # An empty sshd_bin string is falsy, meaning "no sshd"; the error text says so.
    assert err == "sshd binary not found"


# --- read_effective_sshd_config: fallback parser ----------------------------


def test_fallback_parser_first_occurrence_wins_and_hostkey_accumulates(tmp_path: Path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text(
        "# comment\n"
        "HostKey /etc/ssh/one\n"
        "hostkey /etc/ssh/two\n"
        "PermitRootLogin no\n"
        "PermitRootLogin yes\n"
        "AuthorizedKeysFile=.ssh/authorized_keys\n"
    )
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["hostkey"] == ["/etc/ssh/one", "/etc/ssh/two"]
    assert config["permitrootlogin"] == ["no"]
    assert config["authorizedkeysfile"] == [".ssh/authorized_keys"]


def test_fallback_parser_skips_match_blocks(tmp_path: Path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text("StrictModes yes\nMatch User alice\n    AuthorizedKeysFile /nonexistent/%u\n    StrictModes no\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert "authorizedkeysfile" not in config
    assert config["strictmodes"] == ["yes"]


def test_fallback_parser_reads_multiple_files_in_order(tmp_path: Path):
    a = tmp_path / "a.conf"
    b = tmp_path / "b.conf"
    a.write_text("PasswordAuthentication no\n")
    b.write_text("PasswordAuthentication yes\nHostKey /k\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[a, b])
    assert config["passwordauthentication"] == ["no"]
    assert config["hostkey"] == ["/k"]


def test_fallback_parser_ignores_missing_files(tmp_path: Path):
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[tmp_path / "nope"])
    assert config == {}


# --- audit_server_config ------------------------------------------------------


def _msgs(issues: list[audit.Issue]) -> list[str]:
    return [f"{i.severity}:{i.message}" for i in issues]


def test_weak_algorithms_flagged_only_with_sshd_t():
    config = {
        "pubkeyacceptedalgorithms": ["ssh-ed25519,ssh-rsa,ssh-dss"],
        "hostkeyalgorithms": ["ssh-ed25519"],
        "pubkeyacceptedkeytypes": ["ssh-dss"],
    }
    issues, coverage = audit.audit_server_config(config, "sshd -T", "")
    msgs = _msgs(issues)
    assert any("PubkeyAcceptedAlgorithms accepts ssh-rsa" in m for m in msgs)
    assert any("PubkeyAcceptedAlgorithms accepts ssh-dss" in m for m in msgs)
    assert any("PubkeyAcceptedKeyTypes accepts ssh-dss" in m for m in msgs)
    assert not any("HostKeyAlgorithms" in m for m in msgs)
    assert coverage == []

    issues, coverage = audit.audit_server_config(config, "parsed sshd_config", "boom")
    assert not any("accepts" in m for m in _msgs(issues))
    assert coverage and "boom" in coverage[0]


def test_coverage_warnings_for_external_key_sources():
    config = {"authorizedkeyscommand": ["/usr/bin/sss_ssh_authorizedkeys"], "trustedusercakeys": ["/etc/ssh/ca.pub"]}
    _, coverage = audit.audit_server_config(config, "sshd -T", "")
    assert any("AuthorizedKeysCommand" in w and "sss_ssh_authorizedkeys" in w for w in coverage)
    assert any("TrustedUserCAKeys" in w for w in coverage)


def test_none_values_do_not_warn():
    config = {"authorizedkeyscommand": ["none"], "trustedusercakeys": ["none"]}
    _, coverage = audit.audit_server_config(config, "sshd -T", "")
    assert coverage == []


def test_strictmodes_permitrootlogin_password():
    config = {"strictmodes": ["no"], "permitrootlogin": ["yes"], "passwordauthentication": ["yes"]}
    issues, _ = audit.audit_server_config(config, "sshd -T", "")
    msgs = _msgs(issues)
    assert any(m.startswith("MEDIUM:StrictModes") for m in msgs)
    assert any(m.startswith("MEDIUM:PermitRootLogin") for m in msgs)
    assert any(m.startswith("INFO:PasswordAuthentication") for m in msgs)

    issues, _ = audit.audit_server_config(
        {"strictmodes": ["yes"], "permitrootlogin": ["prohibit-password"], "passwordauthentication": ["no"]},
        "sshd -T",
        "",
    )
    assert issues == []


def test_pubkeyauthentication_no_is_coverage_warning():
    _, coverage = audit.audit_server_config({"pubkeyauthentication": ["no"]}, "sshd -T", "")
    assert any("PubkeyAuthentication" in w for w in coverage)
