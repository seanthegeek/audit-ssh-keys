"""Tests for parsing and grading functions that need no filesystem or ssh-keygen."""

from __future__ import annotations

import base64
import pwd
import struct
from pathlib import Path

import pytest

from audit_ssh_keys import audit
from tests.conftest import RICH_VALID_OPTIONS, make_user

# --- split_options -----------------------------------------------------------


def _blob(type_name: str) -> str:
    """A base64 public-key blob that names type_name, the way a real key does.

    Every OpenSSH public key starts with its own type name as the first piece
    of wire data: a 32-bit length followed by that many bytes. The four bytes
    after it stand in for the rest of the key, which nothing here looks at.
    """
    raw = struct.pack(">I", len(type_name)) + type_name.encode("ascii") + struct.pack(">I", 4) + b"xxxx"
    return base64.b64encode(raw).decode("ascii")


@pytest.mark.parametrize(
    "line",
    [
        f"ssh-ed25519 {_blob('ssh-ed25519')} comment",
        f"ssh-rsa {_blob('ssh-rsa')}",
        f"ecdsa-sha2-nistp256 {_blob('ecdsa-sha2-nistp256')} c",
        f"sk-ssh-ed25519@openssh.com {_blob('sk-ssh-ed25519@openssh.com')} c",
        f"ssh-rsa-cert-v01@openssh.com {_blob('ssh-rsa-cert-v01@openssh.com')} c",
        # Added in OpenSSH 10.4 (July 2026); never in any prefix list this
        # tool had, so it proves the structural check.
        f"ssh-mldsa44-ed25519@openssh.com {_blob('ssh-mldsa44-ed25519@openssh.com')} c",
        f"ssh-mldsa44-ed25519-cert-v01@openssh.com {_blob('ssh-mldsa44-ed25519-cert-v01@openssh.com')} c",
    ],
)
def test_split_options_bare_key_has_no_options(line: str):
    assert audit.split_options(line) == ([], line)


@pytest.mark.parametrize("gap", ["  ", "\t", " \t ", "\t\t"])
def test_split_options_skips_every_space_and_tab_between_the_options_and_the_key(gap: str):
    """sshd's skip_space() (misc.c) steps over the whole run of them, not just the first one.

    A single separator hides the difference: the option loop has already
    consumed that one character by the time it returns what is left, so
    dropping the skip entirely would look the same. A run of two or more is
    what tells them apart.
    """
    key = f"ssh-ed25519 {_blob('ssh-ed25519')} c"
    assert audit.split_options(f"no-pty{gap}{key}") == (["no-pty"], key)


@pytest.mark.parametrize("indent", [" ", "\t", "  \t "])
def test_split_options_skips_spaces_and_tabs_at_the_front_of_the_line(indent: str):
    """Those are the two characters sshd skips at the start of a line, so both shapes of line lose them."""
    key = f"ssh-ed25519 {_blob('ssh-ed25519')} c"
    assert audit.split_options(f"{indent}{key}") == ([], key)
    assert audit.split_options(f"{indent}no-pty {key}") == (["no-pty"], key)


def test_split_options_leaves_the_end_of_the_line_alone():
    """Only the front of the line is trimmed; what is on the end is the caller's business.

    str.strip() would take the trailing space off, along with any other
    character Unicode counts as whitespace at either end -- a non-breaking
    space among them, which sshd leaves exactly where it is.
    """
    key = f"ssh-ed25519 {_blob('ssh-ed25519')} c\u00a0 "
    assert audit.split_options(f"no-pty {key}") == (["no-pty"], key)
    assert audit.split_options(key) == ([], key)


@pytest.mark.parametrize(
    "line",
    [
        f"somehost ssh-ed25519 {_blob('ssh-ed25519')} c",
        f"@cert-authority ssh-ed25519 {_blob('ssh-ed25519')} c",
        f"*.example.com,192.0.2.1 ssh-ed25519 {_blob('ssh-ed25519')} c",
        f"|1|c2FsdA==|aGFzaA== ssh-ed25519 {_blob('ssh-ed25519')} c",
    ],
)
def test_is_bare_key_line_rejects_known_hosts_syntax(line: str):
    """A known_hosts line has a host where the key type belongs, so sshd reads no key from it.

    The positive half -- every shape of real key line answering True -- is the
    parametrized test above, which asserts that each of those lines is read as
    having no options at all.
    """
    assert audit._is_bare_key_line(line) is False


def test_split_options_type_name_not_matching_blob_is_treated_as_options():
    """A first field that the blob does not name is not a key, so it reads as options.

    sshd would then fail to parse the rest as a key and skip the line; this
    tool reports it as an unparseable entry.
    """
    opts, rest = audit.split_options(f"ssh-rsa {_blob('ssh-ed25519')} c")
    assert opts == ["ssh-rsa"]
    assert rest == f"{_blob('ssh-ed25519')} c"


def test_split_options_quoted_option_containing_a_type_name():
    blob = _blob("ssh-ed25519")
    opts, rest = audit.split_options(f'command="ssh-rsa x" ssh-ed25519 {blob} c')
    assert opts == ['command="ssh-rsa x"']
    assert rest == f"ssh-ed25519 {blob} c"


def test_split_options_single_field_line_falls_through():
    assert audit.split_options("ssh-ed25519") == (["ssh-ed25519"], "")


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


def test_split_options_backslash_before_anything_but_a_quote_is_not_an_escape():
    r"""Only \" escapes inside a quoted value, so command="a\\" never closes its quote.

    sshd's opt_dequote() (misc.c) and sshkey_advance_past_options() (sshkey.c)
    both skip a character after a backslash only when that character is a
    double quote. Here sshd reads `a`, then the first backslash as a literal
    one, then `\"` as an escaped quote -- so the value runs to the end of the
    line and sshd throws the line out with "missing end quote" instead of
    finding a key on it.
    """
    blob = _blob("ssh-ed25519")
    opts, rest = audit.split_options(rf'command="a\\" ssh-ed25519 {blob} c')
    assert rest == ""
    assert audit.check_options(opts) == "missing end quote"


def test_split_options_escaped_quote_after_a_literal_backslash():
    r"""The same line with the escaped quote closed: the key material survives intact."""
    blob = _blob("ssh-ed25519")
    opts, rest = audit.split_options(rf'command="a\\\" b" ssh-ed25519 {blob} c')
    assert opts == [r'command="a\\\" b"']
    assert rest == f"ssh-ed25519 {blob} c"
    assert audit.check_options(opts) is None


def test_split_options_only_options_is_malformed():
    opts, rest = audit.split_options("no-pty,restrict")
    assert opts == ["no-pty", "restrict"]
    assert rest == ""


def test_split_options_leading_comma_is_skipped():
    """sshd's option loop has no final else, so an empty token just leaves it looking at a comma and skipping it;
    a live OpenSSH 10.2 login accepted ",no-pty <key>"."""
    opts, rest = audit.split_options(",no-pty ssh-ed25519 AAAA")
    assert opts == ["no-pty"]
    assert rest == "ssh-ed25519 AAAA"


def test_split_options_doubled_comma_is_skipped():
    """Same reasoning as the leading-comma case; a live OpenSSH 10.2 login accepted "no-pty,,restrict <key>"."""
    opts, rest = audit.split_options("no-pty,,restrict ssh-ed25519 AAAA")
    assert opts == ["no-pty", "restrict"]
    assert rest == "ssh-ed25519 AAAA"


def test_split_options_trailing_comma_before_the_key_is_dropped():
    """A comma right before the space that ends the options is sshd's loop stopping, not an empty option."""
    opts, rest = audit.split_options("no-pty, ssh-ed25519 AAAA")
    assert opts == ["no-pty"]
    assert rest == "ssh-ed25519 AAAA"


def test_split_options_options_only_trailing_comma_is_dropped():
    """A comma at the very end of an options-only string is "unexpected end-of-options" to sshd, but such a
    line has no key after the options and is already reported as malformed before options are checked."""
    opts, rest = audit.split_options("no-pty,")
    assert opts == ["no-pty"]
    assert rest == ""


# --- check_options -----------------------------------------------------------


@pytest.mark.parametrize(
    "options",
    [
        pytest.param([], id="no options"),
        pytest.param(["restrict"], id="restrict"),
        pytest.param(["no-user-rc", "no-touch-required", "verify-required"], id="negated flags"),
        pytest.param(["NO-PTY", "Cert-Authority"], id="mixed case"),
        pytest.param(['command="a,b"', 'permitopen="h:1"', 'permitopen="h:2"'], id="permitopen may repeat"),
        pytest.param(['environment="1=2"'], id="a digits-only environment name is valid"),
        pytest.param(['environment="A_b9=x=y"'], id="only the name before the first = is checked"),
        pytest.param(['tunnel="5"'], id="numbered tun device"),
        pytest.param(['tunnel=" 5"'], id="leading whitespace before the number"),
        pytest.param(['tunnel="-0"'], id="a signed zero is still device 0"),
        pytest.param(['tunnel="+7"'], id="a plus sign in front of the number"),
        pytest.param(['tunnel="2147483645"'], id="the largest tun device number sshd allows"),
        pytest.param([r'command="a\b"'], id="a backslash before anything but a quote is literal"),
        pytest.param(['tunnel="ANY"'], id="any tun device, case-insensitive"),
        pytest.param(['expiry-time="whatever"'], id="expiry-time contents are not checked"),
        pytest.param(["cert-authority", 'principals="x"'], id="principals after cert-authority"),
        pytest.param(['principals="x"', "cert-authority"], id="principals before cert-authority"),
        pytest.param(['permitlisten="not a port"'], id="permitlisten contents are not checked"),
    ],
)
def test_check_options_accepts_what_sshd_accepts(options: list[str]):
    assert audit.check_options(options) is None


def test_check_options_accepts_a_rich_line_split_by_split_options():
    """The two functions have to compose: split_options' output is check_options' input."""
    options, key_material = audit.split_options(f"{RICH_VALID_OPTIONS} ssh-ed25519 {_blob('ssh-ed25519')} c")
    assert key_material == f"ssh-ed25519 {_blob('ssh-ed25519')} c"
    assert audit.check_options(options) is None


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        pytest.param(["no-port-fowarding"], 'unknown key option "no-port-fowarding"', id="typo"),
        pytest.param(["no-restrict"], 'unknown key option "no-restrict"', id="restrict cannot be negated"),
        pytest.param(
            ["no-cert-authority"], 'unknown key option "no-cert-authority"', id="cert-authority cannot be negated"
        ),
        pytest.param(["pty=x"], 'unknown key option "pty=x"', id="a flag option takes no value"),
        pytest.param(["restricted"], 'unknown key option "restricted"', id="a flag name is not a prefix"),
        pytest.param(["command"], 'unknown key option "command"', id="a value option needs an ="),
        pytest.param(["command=x"], "missing start quote", id="unquoted value"),
        pytest.param(['command="x'], "missing end quote", id="unterminated value"),
        pytest.param(['command="x"y'], 'unknown key option "command="x"y"', id="text after the closing quote"),
        pytest.param(['command="a"', 'command="b"'], 'multiple "command" clauses', id="two commands"),
        pytest.param(['from="a"', 'from="b"'], 'multiple "from" clauses', id="two froms"),
        pytest.param(['principals="a"', 'principals="b"'], 'multiple "principals" clauses', id="two principals"),
        pytest.param(['environment="FOO"'], "invalid environment string", id="environment with no ="),
        pytest.param(['environment="a-b=c"'], "invalid environment string", id="punctuation in an environment name"),
        pytest.param(['environment="=x"'], "invalid environment string", id="empty environment name"),
        pytest.param(['principals="x"'], "principals on non-CA key", id="principals needs cert-authority beside it"),
        pytest.param(
            ["no-pty", 'principals="x"', "restrict"],
            "principals on non-CA key",
            id="restrict does not stand in for cert-authority",
        ),
        pytest.param(['tunnel="x"'], "invalid tun device", id="non-numeric tun device"),
        pytest.param(['tunnel="-1"'], "invalid tun device", id="negative tun device"),
        pytest.param(['tunnel="2147483646"'], "invalid tun device", id="one above the largest tun device number"),
        pytest.param(
            [f'tunnel="{"9" * 5000}"'],
            "invalid tun device",
            id="a tun device number too long for Python to convert",
        ),
        pytest.param(["no-pty", "bogus"], 'unknown key option "bogus"', id="a later option is checked too"),
    ],
)
def test_check_options_rejects_what_sshd_rejects(options: list[str], reason: str):
    assert audit.check_options(options) == reason


def test_check_options_accepts_no_pty_alone():
    assert audit.check_options(["no-pty"]) is None


def test_check_options_rejects_a_typo_split_by_split_options():
    line = f"no-port-fowarding ssh-ed25519 {_blob('ssh-ed25519')} c"
    assert audit.check_options(audit.split_options(line)[0]) == 'unknown key option "no-port-fowarding"'


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


def test_expand_pattern_empty_pw_dir_uses_filesystem_root():
    """An empty pw_dir means the filesystem root to sshd, not the auditing process's cwd.

    make_user stringifies its home argument, so an empty Path("") can't be
    built through it (it would come out as "."). Build the passwd entry by
    hand instead, the way a real account with no home directory looks.
    """
    nohome = pwd.struct_passwd(("nohome", "x", 1000, 1000, "nohome", "", "/bin/sh"))
    assert audit.expand_authorized_keys_pattern(".ssh/authorized_keys", nohome) == "/.ssh/authorized_keys"
    # %h substitutes the raw (empty) pw_dir, giving "" + "/.ssh/authorized_keys" --
    # already absolute, so it is returned as-is. Same result as above, both ways,
    # because sshd's own expand_authorized_keys works the same way.
    assert audit.expand_authorized_keys_pattern("%h/.ssh/authorized_keys", nohome) == "/.ssh/authorized_keys"


def test_expand_pattern_does_not_rescan_substituted_text():
    """sshd's percent_expand() (misc.c) makes a single left-to-right pass: each %x token is replaced by its
    value and the scan continues after the inserted text, so that text is never itself rescanned for more
    tokens. A chained str.replace() implementation gets this wrong -- it replaces %h with the home directory
    and then, as a separate step, replaces any %u/%U left in the *whole* string, including inside the home
    directory it just inserted. A home of "/srv/%u" must come out literally, not with the username spliced in.
    """
    user = pwd.struct_passwd(("srvuser", "x", 1000, 1000, "srvuser", "/srv/%u", "/bin/sh"))
    assert audit.expand_authorized_keys_pattern("%h/.ssh/authorized_keys", user) == "/srv/%u/.ssh/authorized_keys"


def test_expand_pattern_double_percent_is_not_username():
    """%%u is the literal-percent token %% followed by a literal 'u', not %% followed by the %u token."""
    alice = make_user("alice", 1000, Path("/home/alice"))
    assert audit.expand_authorized_keys_pattern("/k/%%u", alice) == "/k/%u"


def test_expand_pattern_username_containing_percent_h_is_not_reexpanded():
    """A username that happens to contain the text '%h' is inserted as-is, not expanded a second time."""
    user = pwd.struct_passwd(("a%hb", "x", 1000, 1000, "a%hb", "/home/a%hb", "/bin/sh"))
    assert audit.expand_authorized_keys_pattern("/keys/%u", user) == "/keys/a%hb"


# --- cfg_value ---------------------------------------------------------------


def test_cfg_value_first_or_default():
    assert audit.cfg_value({"hostkey": ["/a", "/b"]}, "hostkey", "x") == "/a"
    assert audit.cfg_value({}, "hostkey", "x") == "x"
    assert audit.cfg_value({"hostkey": []}, "hostkey", "x") == "x"
