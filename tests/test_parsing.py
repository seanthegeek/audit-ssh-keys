"""Tests for parsing and grading functions that need no filesystem or ssh-keygen."""

from __future__ import annotations

from pathlib import Path

import pytest

from audit_ssh_keys import audit
from tests.conftest import make_user

# --- split_options -----------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "ssh-ed25519 AAAA comment",
        "ssh-rsa AAAA",
        "ecdsa-sha2-nistp256 AAAA c",
        "sk-ssh-ed25519@openssh.com AAAA c",
        "ssh-rsa-cert-v01@openssh.com AAAA c",
    ],
)
def test_split_options_bare_key_has_no_options(line: str):
    assert audit.split_options(line) == ([], line)


def test_split_options_simple():
    opts, rest = audit.split_options("no-pty,no-agent-forwarding ssh-ed25519 AAAA c")
    assert opts == ["no-pty", "no-agent-forwarding"]
    assert rest == "ssh-ed25519 AAAA c"


def test_split_options_quoted_value_with_commas_and_spaces():
    line = 'from="10.0.0.0/8,192.168.1.1",command="/usr/bin/rsync --server, x" ssh-ed25519 AAAA c'
    opts, rest = audit.split_options(line)
    assert opts == ['from="10.0.0.0/8,192.168.1.1"', 'command="/usr/bin/rsync --server, x"']
    assert rest == "ssh-ed25519 AAAA c"


def test_split_options_escaped_quote_inside_value():
    line = r'command="echo \"hi\"" ssh-ed25519 AAAA'
    opts, rest = audit.split_options(line)
    assert opts == [r'command="echo \"hi\""']
    assert rest == "ssh-ed25519 AAAA"


def test_split_options_only_options_is_malformed():
    opts, rest = audit.split_options("no-pty,restrict")
    assert opts == ["no-pty", "restrict"]
    assert rest == ""


# --- pub_sibling ---------------------------------------------------------------


def test_pub_sibling_on_name_with_a_dot():
    assert audit.pub_sibling(Path("/etc/ssh/host.key")) == Path("/etc/ssh/host.key.pub")


def test_pub_sibling_on_plain_name():
    assert audit.pub_sibling(Path("/etc/ssh/ssh_host_rsa_key")) == Path("/etc/ssh/ssh_host_rsa_key.pub")


# --- parse_fingerprint_output ------------------------------------------------


def test_parse_fingerprint_output_basic():
    out = "2048 SHA256:abc/def+ghi user@host (RSA)\n"
    assert audit.parse_fingerprint_output(out) == ("RSA", 2048, "SHA256:abc/def+ghi", "user@host")


def test_parse_fingerprint_output_no_comment_normalised_to_empty():
    out = "256 SHA256:xyz no comment (ED25519)"
    assert audit.parse_fingerprint_output(out) == ("ED25519", 256, "SHA256:xyz", "")


def test_parse_fingerprint_output_comment_with_parentheses():
    out = "256 SHA256:xyz alice (laptop) (ED25519)"
    assert audit.parse_fingerprint_output(out) == ("ED25519", 256, "SHA256:xyz", "alice (laptop)")


def test_parse_fingerprint_output_garbage_is_none():
    assert audit.parse_fingerprint_output("not a fingerprint") is None
    assert audit.parse_fingerprint_output("") is None


# --- grade_key ---------------------------------------------------------------


def _severities(issues: list[audit.Issue]) -> list[str]:
    return [i.severity for i in issues]


def test_grade_key_ed25519_and_ecdsa_clean():
    assert audit.grade_key("ED25519", 256, 3072) == []
    assert audit.grade_key("ECDSA", 256, 3072) == []


def test_grade_key_rsa_thresholds():
    assert audit.grade_key("RSA", 4096, 3072) == []
    assert audit.grade_key("RSA", 3072, 3072) == []
    assert _severities(audit.grade_key("RSA", 2048, 3072)) == ["MEDIUM"]
    assert _severities(audit.grade_key("RSA", 1024, 3072)) == ["CRITICAL"]


def test_grade_key_rsa_below_2048_is_critical_even_with_low_policy():
    # --min-rsa-bits cannot lower the floor below 2048.
    assert _severities(audit.grade_key("RSA", 1024, 1024)) == ["CRITICAL"]
    assert audit.grade_key("RSA", 2048, 2048) == []


def test_grade_key_dsa_and_rsa1():
    assert _severities(audit.grade_key("DSA", 1024, 3072)) == ["HIGH"]
    assert _severities(audit.grade_key("RSA1", 2048, 3072)) == ["CRITICAL"]


# --- grade_options -----------------------------------------------------------


def test_grade_options_root_unrestricted_is_info(tmp_path: Path):
    root = make_user("root", 0, tmp_path)
    assert _severities(audit.grade_options([], root)) == ["INFO"]
    assert _severities(audit.grade_options(["no-pty"], root)) == ["INFO"]


def test_grade_options_root_restricted_is_clean(tmp_path: Path):
    root = make_user("root", 0, tmp_path)
    assert audit.grade_options(['from="10.0.0.1"'], root) == []
    assert audit.grade_options(['command="/bin/true"'], root) == []
    assert audit.grade_options(['FROM="10.0.0.1"'], root) == []  # option names are case-insensitive


def test_grade_options_non_root_never_flagged(tmp_path: Path):
    alice = make_user("alice", 1000, tmp_path)
    assert audit.grade_options([], alice) == []


# --- expand_authorized_keys_pattern -----------------------------------------


def test_expand_pattern_relative_and_tokens(tmp_path: Path):
    alice = make_user("alice", 1000, tmp_path / "alice")
    assert audit.expand_authorized_keys_pattern(".ssh/authorized_keys", alice) == str(
        tmp_path / "alice/.ssh/authorized_keys"
    )
    assert audit.expand_authorized_keys_pattern("/etc/ssh/keys/%u", alice) == "/etc/ssh/keys/alice"
    assert audit.expand_authorized_keys_pattern("%h/.ssh/k", alice) == str(tmp_path / "alice/.ssh/k")
    assert audit.expand_authorized_keys_pattern("/k/%U", alice) == "/k/1000"


def test_expand_pattern_literal_percent(tmp_path: Path):
    alice = make_user("alice", 1000, tmp_path)
    assert audit.expand_authorized_keys_pattern("/k/100%%/%u", alice) == "/k/100%/alice"


# --- cfg_value ---------------------------------------------------------------


def test_cfg_value_first_or_default():
    assert audit.cfg_value({"hostkey": ["/a", "/b"]}, "hostkey", "x") == "/a"
    assert audit.cfg_value({}, "hostkey", "x") == "x"
    assert audit.cfg_value({"hostkey": []}, "hostkey", "x") == "x"
