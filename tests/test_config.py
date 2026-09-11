"""Tests for reading sshd configuration and grading server settings."""

from __future__ import annotations

import os
import pwd
import stat
from pathlib import Path

import pytest

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


def _fake_sshd_with_match(tmp_path: Path) -> str:
    """A fake sshd whose -T output depends on `-C user=`, the way a Match User block would."""
    script = tmp_path / "sshd_match"
    script.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        "  *user=bob*) echo 'authorizedkeysfile /custom/%u' ;;\n"
        "  *) echo 'authorizedkeysfile .ssh/authorized_keys' ;;\n"
        "esac\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


# --- read_user_sshd_config --------------------------------------------------


def test_read_user_sshd_config_applies_match_blocks(tmp_path: Path):
    sshd = _fake_sshd_with_match(tmp_path)
    assert audit.read_user_sshd_config("bob", sshd) == {"authorizedkeysfile": ["/custom/%u"]}
    assert audit.read_user_sshd_config("alice", sshd) == {"authorizedkeysfile": [".ssh/authorized_keys"]}


def test_read_user_sshd_config_is_none_when_sshd_fails(tmp_path: Path):
    assert audit.read_user_sshd_config("bob", _fake_sshd(tmp_path, stdout="strictmodes yes", rc=255)) is None


def test_read_user_sshd_config_is_none_when_sshd_prints_nothing(tmp_path: Path):
    assert audit.read_user_sshd_config("bob", _fake_sshd(tmp_path)) is None


def test_read_user_sshd_config_is_none_when_sshd_cannot_be_run(tmp_path: Path):
    assert audit.read_user_sshd_config("bob", str(tmp_path / "no-such-sshd")) is None


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


def _drop_in(tmp_path: Path, name: str, text: str) -> Path:
    """Write a drop-in config file into tmp_path/"d", creating the directory."""
    directory = tmp_path / "d"
    directory.mkdir(exist_ok=True)
    (directory / name).write_text(text)
    return directory


def test_fallback_parser_include_is_expanded_in_place(tmp_path: Path):
    directory = _drop_in(tmp_path, "10-a.conf", "PermitRootLogin no\n")
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"Include {directory}/*.conf\nPermitRootLogin yes\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    # The included file is read where the Include line sits, so its value is
    # the first one seen and the main file's later line does not override it.
    assert config["permitrootlogin"] == ["no"]


def test_fallback_parser_include_glob_matches_in_sorted_order(tmp_path: Path):
    # Written out of order on purpose: a parser that used directory order
    # instead of sorted order would pick the 20- file here.
    _drop_in(tmp_path, "20-b.conf", "PasswordAuthentication yes\n")
    directory = _drop_in(tmp_path, "10-a.conf", "PasswordAuthentication no\n")
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"Include {directory}/*.conf\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["passwordauthentication"] == ["no"]


def test_fallback_parser_include_inside_match_is_not_followed(tmp_path: Path):
    directory = _drop_in(tmp_path, "10-a.conf", "PermitRootLogin yes\n")
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"StrictModes yes\nMatch User alice\n    Include {directory}/*.conf\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["strictmodes"] == ["yes"]
    assert "permitrootlogin" not in config


def test_fallback_parser_without_include_ignores_sibling_drop_ins(tmp_path: Path):
    drop_ins = tmp_path / "sshd_config.d"
    drop_ins.mkdir()
    (drop_ins / "10-a.conf").write_text("PermitRootLogin yes\n")
    cfg = tmp_path / "sshd_config"
    cfg.write_text("StrictModes yes\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["strictmodes"] == ["yes"]
    # No Include directive, so sshd never looks in sshd_config.d, and neither
    # does the fallback parser.
    assert "permitrootlogin" not in config


def test_fallback_parser_default_reads_only_the_main_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """With no config_paths given, only /etc/ssh/sshd_config is read on its own."""
    drop_ins = tmp_path / "sshd_config.d"
    drop_ins.mkdir()
    (drop_ins / "10-a.conf").write_text("PermitRootLogin yes\n")
    cfg = tmp_path / "sshd_config"
    cfg.write_text("StrictModes yes\n")
    monkeypatch.setattr(audit, "SSHD_CONFIG", cfg)
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="")
    assert config["strictmodes"] == ["yes"]
    assert "permitrootlogin" not in config


def test_fallback_parser_include_with_no_matches_is_ignored(tmp_path: Path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"Include {tmp_path}/no-such-dir/*.conf\nStrictModes yes\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["strictmodes"] == ["yes"]


def test_fallback_parser_self_include_terminates(tmp_path: Path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"Include {cfg}\nStrictModes yes\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["strictmodes"] == ["yes"]


def test_fallback_parser_later_include_does_not_override_an_earlier_value(tmp_path: Path):
    directory = _drop_in(tmp_path, "10-a.conf", "PermitRootLogin yes\n")
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"PermitRootLogin no\nInclude {directory}/*.conf\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    # First occurrence still wins across the Include boundary.
    assert config["permitrootlogin"] == ["no"]


def test_fallback_parser_include_path_with_a_space_can_be_quoted(tmp_path: Path):
    """sshd splits Include arguments the way a shell does, so a path with a space can be quoted."""
    directory = tmp_path / "sp ace"
    directory.mkdir()
    (directory / "10-a.conf").write_text("PermitRootLogin no\n")
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f'Include "{directory}/*.conf"\nPermitRootLogin yes\n')
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["permitrootlogin"] == ["no"]


def test_fallback_parser_include_with_an_unbalanced_quote_is_skipped(tmp_path: Path):
    """An Include sshd would reject outright is skipped, without stopping the parse."""
    directory = _drop_in(tmp_path, "10-a.conf", "PermitRootLogin yes\n")
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f'Include "{directory}/*.conf\nStrictModes yes\n')
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert "permitrootlogin" not in config
    assert config["strictmodes"] == ["yes"]


def test_fallback_parser_relative_include_is_read_from_the_config_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A relative Include argument is looked for in sshd's config directory."""
    _drop_in(tmp_path, "10-a.conf", "PermitRootLogin no\n")
    cfg = tmp_path / "sshd_config"
    cfg.write_text("Include d/*.conf\nPermitRootLogin yes\n")
    monkeypatch.setattr(audit, "SSHD_CONFIG_DIR", tmp_path)
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["permitrootlogin"] == ["no"]


# --- _split_config_args and the fallback parser's argument handling ----------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a b", ["a", "b"]),
        ("  a\t\tb  ", ["a", "b"]),  # leading and repeated whitespace is skipped
        ("", []),
        ("# all comment", []),
        ("a # comment", ["a"]),  # a '#' starting an argument ends the line
        ("a#b", ["a#b"]),  # a '#' inside an argument is an ordinary character
        ('"/dir with space/ak"', ["/dir with space/ak"]),
        ("'single quoted'", ["single quoted"]),
        ('a"b c"d', ["ab cd"]),  # quotes group text and are removed, mid-argument too
        ('a\\"b', ['a"b']),  # \" is an escaped double quote
        ("a\\'b", ["a'b"]),
        ("a\\\\b", ["a\\b"]),  # \\ is an escaped backslash
        ("a\\ b", ["a b"]),  # outside quotes, \<space> is an escaped space
        ("x\\yz", ["x\\yz"]),  # any other backslash is a literal backslash
        ("a\\", ["a\\"]),  # a trailing backslash escapes nothing
        ('"a\\ b"', ["a\\ b"]),  # inside quotes, \<space> is not an escape
        ('"unterminated', None),
        ("'", None),
        ('""', [""]),  # an empty argument, which sshd rejects for the keywords it matters to
    ],
)
def test_split_config_args_matches_sshd(text: str, expected: list[str] | None):
    """_split_config_args mirrors sshd's argv_split(), including its unclosed-quote error."""
    assert audit._split_config_args(text) == expected


def test_fallback_parser_strips_an_inline_comment(tmp_path: Path):
    """sshd ends a line at a '#' that starts an argument, so the comment is not part of the value."""
    cfg = tmp_path / "sshd_config"
    cfg.write_text("StrictModes no # reason we turned it off\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["strictmodes"] == ["no"]


def test_fallback_parser_keeps_a_hash_inside_an_argument(tmp_path: Path):
    """A '#' that does not start an argument is an ordinary character to sshd."""
    cfg = tmp_path / "sshd_config"
    cfg.write_text("AuthorizedKeysFile .ssh/keys#1\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["authorizedkeysfile"] == [".ssh/keys#1"]


def test_fallback_parser_keyword_with_only_a_comment_after_it_is_skipped(tmp_path: Path):
    """A keyword whose only argument is a comment has no value at all, and sshd refuses such a line."""
    cfg = tmp_path / "sshd_config"
    cfg.write_text("StrictModes # nothing here\nPermitRootLogin no\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert "strictmodes" not in config
    assert config["permitrootlogin"] == ["no"]


def test_fallback_parser_keeps_a_quoted_path_with_a_space(tmp_path: Path):
    cfg = tmp_path / "sshd_config"
    cfg.write_text('AuthorizedKeysFile "/x/dir with space/ak"\n')
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["authorizedkeysfile"] == ["/x/dir with space/ak"]


def test_fallback_parser_honours_backslash_escapes(tmp_path: Path):
    r"""\" is a double quote and \\ is a single backslash, as sshd's argv_split() reads them."""
    cfg = tmp_path / "sshd_config"
    cfg.write_text('AuthorizedKeysFile a\\"b c\\\\d\n')
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    # Two arguments, stored joined with a single space the way `sshd -T` prints them.
    assert config["authorizedkeysfile"] == ['a"b c\\d']


def test_fallback_parser_skips_a_line_with_an_unclosed_quote(tmp_path: Path):
    """sshd refuses the whole config over an unclosed quote, so the line is skipped -- but the file is read on."""
    cfg = tmp_path / "sshd_config"
    cfg.write_text('AuthorizedKeysFile "/unterminated\nStrictModes no\n')
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert "authorizedkeysfile" not in config
    assert config["strictmodes"] == ["no"]


def test_fallback_parser_expands_a_leading_tilde(tmp_path: Path):
    """sshd tilde-expands AuthorizedKeysFile and HostKey arguments against the uid running it."""
    running_home = pwd.getpwuid(os.getuid()).pw_dir.rstrip("/")
    cfg = tmp_path / "sshd_config"
    cfg.write_text("AuthorizedKeysFile ~/keys/%u\nHostKey ~/hostkey\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["authorizedkeysfile"] == [f"{running_home}/keys/%u"]
    assert config["hostkey"] == [f"{running_home}/hostkey"]


def test_fallback_parser_expands_a_tilde_account_name(tmp_path: Path):
    """'~name' is that account's home directory, which sshd looks up the same way."""
    running = pwd.getpwuid(os.getuid())
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"AuthorizedKeysFile ~{running.pw_name}/keys\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["authorizedkeysfile"] == [f"{running.pw_dir.rstrip('/')}/keys"]


def test_fallback_parser_leaves_an_unknown_tilde_account_alone(tmp_path: Path):
    """There is no home directory to expand to for an account that does not exist, and sshd refuses the config."""
    cfg = tmp_path / "sshd_config"
    cfg.write_text("AuthorizedKeysFile ~no-such-account-here/keys\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["authorizedkeysfile"] == ["~no-such-account-here/keys"]


def test_fallback_parser_makes_a_relative_hostkey_absolute(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """sshd resolves a relative HostKey against its own working directory; the fallback can only use this one."""
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "sshd_config"
    cfg.write_text("HostKey etc/ssh_host_ed25519_key\nAuthorizedKeysFile .ssh/authorized_keys\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["hostkey"] == [str(tmp_path / "etc" / "ssh_host_ed25519_key")]
    # Only HostKey is made absolute: an AuthorizedKeysFile pattern is relative
    # to each account's home directory, and is expanded per account later.
    assert config["authorizedkeysfile"] == [".ssh/authorized_keys"]


def test_fallback_parser_leaves_hostkey_none_alone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """sshd's derelativise_path() checks for 'none' first and does not turn it into a path."""
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "sshd_config"
    cfg.write_text("HostKey none\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["hostkey"] == ["none"]


def test_fallback_parser_leaves_a_tilde_alone_when_the_running_uid_has_no_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A uid with no passwd entry (a container started with an arbitrary uid) has no home to expand to."""

    def no_such_uid(uid: int) -> pwd.struct_passwd:
        raise KeyError(f"getpwuid(): uid not found: {uid}")

    monkeypatch.setattr(audit.pwd, "getpwuid", no_such_uid)
    cfg = tmp_path / "sshd_config"
    cfg.write_text("AuthorizedKeysFile ~/keys/%u\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["authorizedkeysfile"] == ["~/keys/%u"]


@pytest.mark.parametrize(
    "line",
    [
        pytest.param("StrictModes=no", id="no spaces"),
        pytest.param("StrictModes = no", id="spaces either side"),
        pytest.param("StrictModes =no", id="space before only"),
        pytest.param("StrictModes= no", id="space after only"),
    ],
)
def test_fallback_parser_accepts_an_equals_separator(tmp_path: Path, line: str):
    """sshd accepts `Keyword=value`, with or without spaces around the `=`, as well as `Keyword value`.

    strdelim_internal() (misc.c) skips the first '=' it finds and the
    whitespace on either side of it, so all four spellings give the same value.
    Verified against OpenSSH 10.2: `sshd -T` prints `strictmodes no` for each.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text(line + "\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["strictmodes"] == ["no"]


def test_fallback_parser_keeps_a_second_equals_in_the_value(tmp_path: Path):
    """Only one '=' is ever skipped, and it is the one that ends the keyword.

    strdelim_internal() (misc.c) skips an '=' after the keyword only when the
    keyword did not already end at one, so "StrictModes==no" has the value
    "=no". Verified against OpenSSH 10.2, which refuses the config with
    `unsupported option "=no"` -- which is why the fallback parser is the code
    that reads such a file, and why it must not quietly read it as "no".
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text("StrictModes==no\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["strictmodes"] == ["=no"]


def test_fallback_parser_strips_the_equals_from_a_path_value(tmp_path: Path):
    """The '=' separator must not end up inside the value, which a path keyword would make visible."""
    host_key = tmp_path / "ssh_host_ed25519_key"
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"StrictModes = no\nHostKey = {host_key}\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert config["strictmodes"] == ["no"]
    assert config["hostkey"] == [str(host_key)]


def test_fallback_parser_skips_a_match_block_opened_by_a_malformed_match_line(tmp_path: Path):
    """A Match line sshd would reject still opens a block, so its body must not be read as global config.

    sshd refuses the whole configuration over the unclosed quote here
    ("line 1: invalid quotes ... terminating, 1 bad configuration options",
    verified against OpenSSH 10.2). The dangerous reading is to treat the
    Match line as unusable and carry on: the block's own AuthorizedKeysFile
    would become the global pattern, and no account's real file would ever be
    scanned.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text('Match User "alice\nPermitRootLogin yes\nAuthorizedKeysFile .ssh/match_only\n')
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert "permitrootlogin" not in config
    assert "authorizedkeysfile" not in config


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
    # The fallback parser skips Match blocks, so the warning has to say so.
    assert "Match blocks were not applied" in coverage[0]


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
