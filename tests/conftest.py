"""Shared fixtures.

Key material is generated fresh with ssh-keygen in a temp directory, so tests
exercise the real parsing path without checking any keys into the repo.
"""

from __future__ import annotations

import contextlib
import os
import pwd
import shutil
import subprocess
from pathlib import Path

import pytest

HAVE_SSH_KEYGEN = shutil.which("ssh-keygen") is not None
IS_ROOT = os.geteuid() == 0
# A uid for "ordinary user" fixtures. Files we create are owned by the real uid; when that is
# root, sshd accepts root-owned files for any account, so any non-zero uid works.
USER_UID = os.getuid() or 1000

needs_ssh_keygen = pytest.mark.skipif(not HAVE_SSH_KEYGEN, reason="ssh-keygen not installed")
needs_root = pytest.mark.skipif(not IS_ROOT, reason="requires root to chown")
# A permission error can only be observed when the test itself is not root:
# root ignores a directory's permission bits entirely, so chmod(0o000) would
# not reproduce anything for it to see.
needs_non_root = pytest.mark.skipif(IS_ROOT, reason="root ignores permission bits, so this needs a non-root run")

# A line using every option shape sshd accepts: flag options plain and
# negated, mixed case, an escaped quote and a comma inside a quoted value.
RICH_VALID_OPTIONS = (
    'restrict,command="echo \\"hi\\",there",from="10.0.0.0/8,!10.0.0.1",environment="FOO=bar",'
    'permitopen="host:22",permitlisten="8080",tunnel="any",expiry-time="20300101",'
    "no-pty,No-Port-Forwarding,cert-authority"
)


def make_user(name: str, uid: int, home: Path) -> pwd.struct_passwd:
    """Build a passwd entry pointing at a temp home directory."""
    return pwd.struct_passwd((name, "x", uid, uid, name, str(home), "/bin/sh"))


def mkdir_clean(path: Path, root: Path, mode: int = 0o755) -> Path:
    """Create path (and any missing parents), then force an exact mode regardless of the caller's umask.

    A bare `mkdir()` (or `mkdir(parents=True)`) inherits the umask, so under
    umask 002 it yields a group-writable directory (mode 0775) even when the
    call site never asked for one. sshd -- and this tool's own permission
    checks -- reject a group-writable home directory or `~/.ssh`, so tests
    that build fake accounts need a umask-independent layout. This chmods
    `path` and every parent directory up to (but not including) `root`.
    """
    path.mkdir(parents=True, exist_ok=True)
    p = path
    while p != root and p.is_relative_to(root):
        p.chmod(mode)
        p = p.parent
    return path


def keygen(path: Path, key_type: str, bits: int | None = None, passphrase: str = "", comment: str = "") -> Path:
    """Generate a key pair with ssh-keygen and return the private key path."""
    cmd = ["ssh-keygen", "-q", "-t", key_type, "-f", str(path), "-N", passphrase, "-C", comment]
    if bits:
        cmd += ["-b", str(bits)]
    subprocess.run(cmd, check=True, capture_output=True, stdin=subprocess.DEVNULL)
    return path


@pytest.fixture(scope="session")
def keys(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """One of each interesting key type; returns {name: private_key_path}."""
    if not HAVE_SSH_KEYGEN:
        pytest.skip("ssh-keygen not installed")
    d = tmp_path_factory.mktemp("keys")
    out = {
        "ed25519": keygen(d / "ed25519", "ed25519", comment="ed@test"),
        "rsa2048": keygen(d / "rsa2048", "rsa", 2048, comment="rsa2048@test"),
        "rsa4096": keygen(d / "rsa4096", "rsa", 4096, comment="rsa4096@test"),
        "rsa1024": keygen(d / "rsa1024", "rsa", 1024, comment="rsa1024@test"),
        "ecdsa": keygen(d / "ecdsa", "ecdsa", 256, comment="ecdsa@test"),
        "encrypted": keygen(d / "encrypted", "ed25519", passphrase="hunter2", comment="enc@test"),
    }
    # DSA is disabled at build time in some OpenSSH packages; include it when available.
    with contextlib.suppress(subprocess.CalledProcessError):
        out["dsa"] = keygen(d / "dsa", "dsa", comment="dsa@test")
    return out


def pub(private_key: Path) -> str:
    """Public-key line for a generated private key."""
    return private_key.with_name(private_key.name + ".pub").read_text().strip()


@pytest.fixture
def current_user_at(tmp_path: Path) -> pwd.struct_passwd:
    """A passwd entry for the *real* current uid, but with HOME under tmp_path.

    Using the real uid means files we create are owned by the "user" without chown.
    """
    home = tmp_path / "home"
    mkdir_clean(home, tmp_path)
    return make_user("tester", os.getuid(), home)
