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


def _fake_sshd_printing_raw_bytes(tmp_path: Path, name: str, stdout: str = "", stderr: str = "", rc: int = 0) -> str:
    """A fake sshd whose output is written by `printf` from an escaped string.

    The text is handed to `printf` as its format string, so an escape in it
    reaches the pipe as the bytes it names: `\\344` as that one raw byte -- the
    way sshd prints a config value that holds a byte from some other encoding,
    since it copies the file's bytes rather than transcoding them -- and `\\t`
    or `\\n` as the whitespace it stands for. Callers that need none of those
    escapes use _fake_sshd above, whose output is printed as a literal string.
    """
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\nprintf '{stdout}'\nprintf '{stderr}' >&2\nexit {rc}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def test_sshd_t_output_holding_a_byte_that_is_not_utf8_is_read_not_a_crash(tmp_path: Path):
    """A config value can hold a byte that is not valid UTF-8, and sshd -T prints it as it stands.

    Decoding that output strictly raised UnicodeDecodeError, which is not an
    OSError and so escaped the guard around the call: the audit ended before it
    could even fall back to parsing the config file, whose own parser replaces
    such a byte rather than choking on it.
    """
    sshd = _fake_sshd_printing_raw_bytes(
        tmp_path,
        "sshd_raw",
        stdout="banner /etc/ssh/b\\344nner\\nauthorizedkeysfile .ssh/authorized_keys\\n",
    )
    config, source, err = audit.read_effective_sshd_config(sshd_bin=sshd)

    assert source == "sshd -T"
    assert err == ""
    assert config["banner"] == ["/etc/ssh/b\ufffdnner"]
    assert config["authorizedkeysfile"] == [".ssh/authorized_keys"]


def test_sshd_t_stderr_holding_a_byte_that_is_not_utf8_still_reaches_the_coverage_warning(tmp_path: Path):
    """The stderr of a failed sshd -T is quoted into a finding, so it has to survive the same byte."""
    cfg = tmp_path / "sshd_config"
    cfg.write_text("AuthorizedKeysFile /custom/%u\n")
    sshd = _fake_sshd_printing_raw_bytes(
        tmp_path, "sshd_raw_err", stderr="Unable to load host key: /etc/ssh/b\\344d\\n", rc=255
    )
    config, source, err = audit.read_effective_sshd_config(sshd_bin=sshd, config_paths=[cfg])

    assert source.startswith("parsed sshd_config")
    assert err == "Unable to load host key: /etc/ssh/b\ufffdd"
    assert config["authorizedkeysfile"] == ["/custom/%u"]


def test_read_user_sshd_config_reads_output_holding_a_byte_that_is_not_utf8(tmp_path: Path):
    """The per-account run decodes the same way; strict decoding ended the audit instead of returning None."""
    sshd = _fake_sshd_printing_raw_bytes(
        tmp_path, "sshd_raw_user", stdout="banner /etc/ssh/b\\344nner\\nauthorizedkeysfile /custom/keys\\n"
    )
    assert audit.read_user_sshd_config("bob", sshd) == {
        "banner": ["/etc/ssh/b\ufffdnner"],
        "authorizedkeysfile": ["/custom/keys"],
    }


def test_sshd_t_value_holding_a_line_separator_is_read_as_one_line(tmp_path: Path):
    """`sshd -T` prints each value as the bytes the config file holds, so a value can hold a line break.

    Python's own line splitting breaks on a vertical tab, a form feed, U+2028
    and more, none of which end a line for sshd, whose getline() ends one at a
    newline and at nothing else. A Banner path holding a U+2028 therefore read
    as two lines, and the tail of it became a keyword line in its own right --
    here it would have set this host's AuthorizedKeysFile to /evil/%u. Only
    root writes sshd_config, so this is a consistency fix rather than a way
    in: it is the same split _parse_sshd_config_file makes, and the two
    parsers have to agree about what a line is.
    """
    sshd = _fake_sshd_printing_raw_bytes(
        tmp_path,
        "sshd_line_separator",
        # \342\200\250 is U+2028 in UTF-8, and %%u reaches printf as a literal %u.
        stdout="banner /etc/ssh/b\\342\\200\\250authorizedkeysfile /evil/%%u\\nauthorizedkeysfile .ssh/ok\\n",
    )
    config, source, err = audit.read_effective_sshd_config(sshd_bin=sshd)

    assert source == "sshd -T"
    assert err == ""
    assert config["banner"] == ["/etc/ssh/b\u2028authorizedkeysfile /evil/%u"]
    assert config["authorizedkeysfile"] == [".ssh/ok"]


def test_config_file_value_holding_a_line_separator_is_read_as_one_line(tmp_path: Path):
    """The fallback parser splits the file the same way, and for the same reason.

    sshd reads sshd_config with getline() too (load_server_config() in
    servconf.c), so one of these characters inside a value does not start a
    new directive. Splitting on them let the tail of a Banner path set
    AuthorizedKeysFile, which -- because the first value seen for a keyword
    wins -- displaced the real setting further down the file.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text("Banner /etc/ssh/b\u2028AuthorizedKeysFile /evil/%u\nAuthorizedKeysFile .ssh/ok\n", encoding="utf-8")

    config, source, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])

    assert source.startswith("parsed sshd_config")
    assert config["banner"] == ["/etc/ssh/b\u2028AuthorizedKeysFile /evil/%u"]
    assert config["authorizedkeysfile"] == [".ssh/ok"]


def test_config_file_value_holding_a_carriage_return_is_read_as_one_line(tmp_path: Path):
    """A bare carriage return inside a value does not start a new directive either.

    Splitting the text on newlines is only half of it: Python's default text
    mode turns a lone carriage return, and a carriage return followed by a
    newline, into a newline as the file is read, so the split saw two lines
    where the file holds one. sshd reads the file with getline(), which ends a
    line at a newline and at nothing else, and its argv_split() (misc.c) then
    ends an argument at a space or a tab and at nothing else, so the carriage
    return stays inside the value. Verified against OpenSSH_10.2p1, whose
    `sshd -T` prints this file's Banner with the carriage return still in it,
    and its AuthorizedKeysFile as `.ssh/ok`.

    The keyword injected here is the one that decides which files this tool
    scans, and because the first value seen for a keyword wins, it displaced
    the real setting further down the file.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_bytes(b"Banner /etc/ssh/b\rAuthorizedKeysFile=/evil/%u\nAuthorizedKeysFile .ssh/ok\n")

    config, source, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])

    assert source.startswith("parsed sshd_config")
    assert config["banner"] == ["/etc/ssh/b\rAuthorizedKeysFile=/evil/%u"]
    assert config["authorizedkeysfile"] == [".ssh/ok"]


@pytest.mark.parametrize(
    ("name", "character"),
    [("non-breaking space", "\u00a0"), ("line separator", "\u2028")],
)
def test_fallback_parser_keeps_trailing_whitespace_that_sshd_keeps(tmp_path: Path, name: str, character: str):
    r"""sshd trims " \t\r\n" and a form feed off the end of a line, and nothing else.

    That is the "Strip trailing whitespace" loop at the top of
    process_server_config_line_depth() (servconf.c). str.strip() trims
    everything Unicode counts as whitespace, which is a good deal more.
    Verified against OpenSSH_10.2p1: an AuthorizedKeysFile ending in a
    non-breaking space is printed by `sshd -T` with that space still on the
    end, so it names a file whose name ends in one, and this parser has to
    read the same value.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"AuthorizedKeysFile /custom/%u{character}\n", encoding="utf-8")

    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])

    assert config["authorizedkeysfile"] == [f"/custom/%u{character}"]


def test_fallback_parser_skips_only_the_leading_whitespace_sshd_skips(tmp_path: Path):
    r"""sshd steps over a run of " \t\r" at the front of a line, and over nothing else.

    load_server_config() (servconf.c) does that with
    `cp = line + strspn(line, " \t\r")`. A non-breaking space is not in that
    set, so it stays where it is and becomes the first character of the
    keyword: OpenSSH_10.2p1 refuses this file with `Bad configuration option:
    \302\240AuthorizedKeysFile`. str.strip() took that space off and read the
    line as an AuthorizedKeysFile setting -- and, because the first value seen
    for a keyword wins, that setting displaced the real one.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text("\u00a0AuthorizedKeysFile /evil/%u\n \t\rAuthorizedKeysFile .ssh/ok\n", encoding="utf-8")

    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])

    # The second line proves the other half of the claim: the three characters
    # sshd does skip are still skipped, so that line is read as a setting.
    assert config["authorizedkeysfile"] == [".ssh/ok"]


def test_fallback_parser_does_not_take_a_non_breaking_space_for_a_keyword_separator(tmp_path: Path):
    r"""A keyword ends at sshd's own whitespace or an '=', not at everything Python calls whitespace.

    strdelim_internal() (misc.c) ends the keyword at one of WHITESPACE
    " \t\r\n" or at an '='. (A quote stops its search too, but it does not end
    the keyword there -- it joins the text on either side of it into one
    keyword instead; see test_split_config_keyword_matches_sshd.) A
    non-breaking space is none of those, so the keyword runs on through it and
    sshd refuses the line --
    `no argument after keyword "AuthorizedKeysFile\302\240/evil/%u"` against
    OpenSSH_10.2p1. The regular expression that finds the separator here used
    Python's \s, which does match a non-breaking space, so this tool honoured
    a setting sshd will not even start with.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text("AuthorizedKeysFile\u00a0/evil/%u\nAuthorizedKeysFile .ssh/ok\n", encoding="utf-8")

    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])

    assert config["authorizedkeysfile"] == [".ssh/ok"]


def test_fallback_parser_keeps_whitespace_sshd_keeps_at_the_front_of_a_value(tmp_path: Path):
    r"""Only sshd's own whitespace is skipped between a keyword and its value.

    strdelim_internal() (misc.c) skips a run of WHITESPACE " \t\r\n" after the
    keyword, and argv_split() (misc.c) then ends an argument at a space or a
    tab, so a non-breaking space in front of the value is part of the value.
    str.lstrip() with no argument took it off, naming a different file from
    the one sshd opens.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text("AuthorizedKeysFile \u00a0/custom/%u\n", encoding="utf-8")

    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])

    assert config["authorizedkeysfile"] == ["\u00a0/custom/%u"]


def test_sshd_t_value_keeps_the_whitespace_sshd_printed(tmp_path: Path):
    r"""`sshd -T` prints the value it stored, so nothing may be trimmed off either end of it.

    sshd prints one space between the keyword and the value (`printf("%s
    %s\n", ...)` in the dump_cfg_* helpers in servconf.c) and then the value as
    it stands. A quoted value in sshd_config can start or end with whitespace
    that sshd keeps: verified against OpenSSH_10.2p1, for an
    AuthorizedKeysFile whose quoted value is a space, `.ssh/ak`, and a tab,
    `sshd -T` prints the keyword, the one separating space, and then that
    value with both the space and the tab still on it -- so sshd goes looking
    for a file whose name begins with a space and ends with a tab. Splitting
    on any run of whitespace swallowed the leading space, and str.strip() the
    trailing tab, so this tool went looking for a different file from the one
    sshd reads.
    """
    sshd = _fake_sshd_printing_raw_bytes(tmp_path, "sshd_padded_value", stdout="authorizedkeysfile  .ssh/ak\\t\\n")

    config, source, err = audit.read_effective_sshd_config(sshd_bin=sshd)

    assert source == "sshd -T"
    assert err == ""
    assert config["authorizedkeysfile"] == [" .ssh/ak\t"]


def test_sshd_t_line_with_no_value_after_the_keyword_is_skipped(tmp_path: Path):
    """A line that is a keyword and nothing else names no value, so it is not recorded.

    Every keyword `sshd -T` prints comes with a value, so this is about what
    the parser does with a line it should never see rather than about sshd.
    Recording an empty value would be worse than dropping the line: a caller
    asking for hostkeyagent, say, would be handed "" and read it as an agent
    that is configured.
    """
    sshd = _fake_sshd_printing_raw_bytes(
        tmp_path, "sshd_bare_keyword", stdout="hostkeyagent\\nhostkeyagent \\nauthorizedkeysfile .ssh/ak\\n"
    )

    config, _, _ = audit.read_effective_sshd_config(sshd_bin=sshd)

    assert "hostkeyagent" not in config
    assert config["authorizedkeysfile"] == [".ssh/ak"]


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


# --- _split_config_keyword and the fallback parser's keyword handling --------


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        # The everyday shapes: whitespace, an '=', and both together.
        ("AuthorizedKeysFile .ssh/ok", ("AuthorizedKeysFile", ".ssh/ok")),
        ("AuthorizedKeysFile\t\t.ssh/ok", ("AuthorizedKeysFile", ".ssh/ok")),
        ("AuthorizedKeysFile=.ssh/ok", ("AuthorizedKeysFile", ".ssh/ok")),
        ("AuthorizedKeysFile = .ssh/ok", ("AuthorizedKeysFile", ".ssh/ok")),
        # Only one '=' is ever skipped, so the second one starts the value.
        ("AuthorizedKeysFile==.ssh/ok", ("AuthorizedKeysFile", "=.ssh/ok")),
        # A quote does not end the keyword: it is taken out, and the text on
        # either side of it is joined into one keyword.
        ('Authorized"KeysFile" /evil/%u', ("AuthorizedKeysFile", "/evil/%u")),
        ('"AuthorizedKeysFile" /evil/%u', ("AuthorizedKeysFile", "/evil/%u")),
        # No whitespace is needed after the closing quote.
        ('Authorized"KeysFile"/evil/%u', ("AuthorizedKeysFile", "/evil/%u")),
        # ... so a quoted value written with no space in front of it becomes
        # part of the keyword, and the line has no value at all.
        ('AuthorizedKeysFile"/evil/%u"', ("AuthorizedKeysFile/evil/%u", "")),
        # An '=' after a quoted keyword is not skipped; it starts the value.
        ('"AuthorizedKeysFile"=/evil/%u', ("AuthorizedKeysFile", "=/evil/%u")),
        # Only one pair of quotes is handled: the keyword ends at the closing
        # quote, and a second quoted run is left for the value.
        ('Auth"orized"KeysFile /evil/%u', ("Authorized", "KeysFile /evil/%u")),
        # An empty first token is answered with one more token, so both of
        # these set AuthorizedKeysFile.
        ('""AuthorizedKeysFile /evil/%u', ("AuthorizedKeysFile", "/evil/%u")),
        ("=AuthorizedKeysFile /evil/%u", ("AuthorizedKeysFile", "/evil/%u")),
        # A line with no separator at all is all keyword and has no value.
        ("Match", ("Match", "")),
        # A form feed is not one of sshd's separators, so it is a keyword.
        ("\f", ("\f", "")),
        # Only sshd's own whitespace separates a keyword from its value.
        ("AuthorizedKeysFile \u00a0/evil/%u", ("AuthorizedKeysFile", "\u00a0/evil/%u")),
        # No keyword to be had: a quote that is never closed, and lines that
        # hold nothing but separators.
        ('Authorized"KeysFile /evil/%u', None),
        ('"', None),
        ('""', None),
        ("=", None),
    ],
)
def test_split_config_keyword_matches_sshd(line: str, expected: tuple[str, str] | None):
    """The keyword is read the way strdelim_internal() (misc.c) reads a token, quotes and all.

    Every row was run against OpenSSH_10.2p1's `sshd -T`: the rows whose
    keyword is AuthorizedKeysFile print that setting with the value this row
    names, the rows whose keyword is something else are refused as a bad
    configuration option or as a keyword with no argument, and the four None
    rows leave AuthorizedKeysFile at its default with the configuration still
    loading. The quoting rows are the ones that used to be read wrongly: a
    quote was not a character this parser knew, so
    `Authorized"KeysFile" /evil/%u` was filed under a keyword of its own and
    the audit went on to read whatever .ssh/ok further down the file named,
    while sshd read the file in /evil.
    """
    assert audit._split_config_keyword(line) == expected


def test_fallback_parser_reads_a_keyword_written_with_quotes_in_it(tmp_path: Path):
    """A quoted keyword names the same setting as the unquoted spelling, so it must not be missed.

    Verified against OpenSSH_10.2p1: for this file `sshd -T` prints
    `authorizedkeysfile /evil/%u`. The .ssh/ok line below it is the trap --
    the first value seen for a keyword wins, so a parser that does not
    recognise the quoted keyword audits .ssh/ok while sshd is reading
    /evil/%u.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text('Authorized"KeysFile" /evil/%u\nAuthorizedKeysFile .ssh/ok\n')

    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])

    assert config["authorizedkeysfile"] == ["/evil/%u"]


@pytest.mark.parametrize("prefix", ['""', "="], ids=["empty-quotes", "equals"])
def test_fallback_parser_reads_a_keyword_after_an_empty_first_token(tmp_path: Path, prefix: str):
    """A line starting with an '=' or an empty pair of quotes still sets the keyword after it.

    strdelim() hands back an empty token for either one, and
    process_server_config_line_depth() (servconf.c) asks for one more rather
    than dropping the line: OpenSSH_10.2p1 prints `authorizedkeysfile
    /evil/%u` for both spellings.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text(f"{prefix}AuthorizedKeysFile /evil/%u\nAuthorizedKeysFile .ssh/ok\n")

    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])

    assert config["authorizedkeysfile"] == ["/evil/%u"]


def test_fallback_parser_ignores_a_line_whose_keyword_opens_a_quote_and_never_closes_it(tmp_path: Path):
    """sshd reads no keyword from such a line and passes over it in silence, so nothing may be filed under it.

    strdelim() returns NULL for an unclosed quote, which
    process_server_config_line_depth() treats as end of line. The
    configuration still loads: verified against OpenSSH_10.2p1, this file
    leaves AuthorizedKeysFile at its default and `sshd -T` prints no error at
    all -- so the .ssh/ok line below is the one that counts, and the ignored
    line must leave no keyword of its own behind.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text('Authorized"KeysFile /evil/%u\nAuthorizedKeysFile .ssh/ok\n')

    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])

    assert config == {"authorizedkeysfile": [".ssh/ok"]}


def test_fallback_parser_reads_a_file_with_crlf_line_endings(tmp_path: Path):
    """A config file written on Windows must read like any other, carriage returns and all.

    The file is split at newlines alone, so every line arrives with a carriage
    return still on the end of it, and taking that off is the job of
    SSHD_CONFIG_TRAILING_WHITESPACE -- sshd's own "Strip trailing whitespace"
    loop, which walks back over " \\t\\r\\n" and a form feed. A carriage
    return left on the end would land inside the value: the AuthorizedKeysFile
    pattern would name a file whose name ends in one, and StrictModes would be
    read as "no\\r" rather than as "no".
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_bytes(b"StrictModes no\r\nAuthorizedKeysFile .ssh/ok\r\nPermitRootLogin no\r\n")

    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])

    assert config == {
        "strictmodes": ["no"],
        "authorizedkeysfile": [".ssh/ok"],
        "permitrootlogin": ["no"],
    }


def test_fallback_parser_takes_a_form_feed_off_the_end_of_a_line(tmp_path: Path):
    """A form feed is trimmed off the end of a line, and off that end only.

    It is the one character sshd's trailing set holds that its leading set
    does not (the "Strip trailing whitespace" loop walks back over WHITESPACE
    plus a form feed, while load_server_config() steps over " \\t\\r" at the
    front). Verified against OpenSSH_10.2p1: `sshd -T` prints
    `authorizedkeysfile /evil/%u` for a line ending in a form feed, and
    refuses a file whose line begins with one (`Bad configuration option:
    \\014AuthorizedKeysFile`), which is why the second line here is not read
    as a setting.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text("AuthorizedKeysFile /evil/%u\f\n\fStrictModes no\n")

    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])

    assert config["authorizedkeysfile"] == ["/evil/%u"]
    assert "strictmodes" not in config


def test_fallback_parser_ignores_a_line_that_is_nothing_but_a_form_feed(tmp_path: Path):
    """Such a line holds no setting here, and sshd refuses the whole configuration over it.

    str.rstrip() empties the line and it is skipped as blank. sshd's loop
    stops before the first character instead, leaving a keyword one form feed
    long, which it then refuses: `no argument after keyword "\\014"`, verified
    against OpenSSH_10.2p1. That divergence is recorded on
    SSHD_CONFIG_TRAILING_WHITESPACE; either reading ends with the line
    contributing nothing, and the lines around it are still read.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text("\f\nAuthorizedKeysFile .ssh/ok\nStrictModes no\n")

    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])

    assert config == {"authorizedkeysfile": [".ssh/ok"], "strictmodes": ["no"]}


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


def test_fallback_parser_leaves_an_unknown_tilde_account_alone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """There is no home directory to expand to for an account that does not exist, and sshd refuses the config."""

    def no_such_account(name: str) -> pwd.struct_passwd:
        raise KeyError(f"getpwnam(): name not found: {name}")

    monkeypatch.setattr(audit.pwd, "getpwnam", no_such_account)
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


def test_fallback_parser_treats_a_bare_match_line_as_opening_a_block(tmp_path: Path):
    """A line that is just "Match" has no value on it, and must still open a block.

    sshd refuses a configuration like this one outright ("line 1: no argument
    after keyword \"Match\"", verified against OpenSSH 10.2) -- which is one of
    the reasons this fallback parser would be running at all. Reading the
    block's body as global configuration would be the worst answer: the
    PermitRootLogin below would be reported as the host's global setting when
    sshd applies it to nobody.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text("Match\nPermitRootLogin yes\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert "permitrootlogin" not in config


def test_fallback_parser_ignores_a_keyword_with_no_value_and_keeps_reading(tmp_path: Path):
    """A line holding nothing but a keyword has no value to store, and must not stop the rest of the file.

    sshd refuses a configuration like this one outright ("line 1: no argument
    after keyword \"PermitRootLogin\"", verified against OpenSSH 10.2), which is
    one of the reasons this fallback parser would be running. Only a bare
    "Match" means anything on a line that carries no value; every other
    keyword is dropped, no value is invented for it, and the keywords below it
    still parse.
    """
    cfg = tmp_path / "sshd_config"
    cfg.write_text("PermitRootLogin\nStrictModes no\n")
    config, _, _ = audit.read_effective_sshd_config(sshd_bin="", config_paths=[cfg])
    assert "permitrootlogin" not in config
    assert config["strictmodes"] == ["no"]


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
