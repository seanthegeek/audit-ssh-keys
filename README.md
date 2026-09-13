# audit-ssh-keys

[![CI](https://github.com/seanthegeek/audit-ssh-keys/actions/workflows/ci.yml/badge.svg)](https://github.com/seanthegeek/audit-ssh-keys/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/seanthegeek/audit-ssh-keys/graph/badge.svg)](https://codecov.io/gh/seanthegeek/audit-ssh-keys)

Audit every SSH key on a Linux server in one pass: the server's own host keys,
every account's `authorized_keys`, and any private keys sitting in `~/.ssh`.

It reads the *effective* `sshd` configuration (via `sshd -T`) so it checks the
files `sshd` will actually consult — including custom `AuthorizedKeysFile`
locations and home directories outside `/home` — and tells you when `sshd` is
sourcing keys from somewhere a file audit cannot see.

```text
$ sudo python3 audit-ssh-keys.py
sshd config source: sshd -T

=== Server configuration ===
  [MEDIUM] PubkeyAcceptedAlgorithms accepts ssh-rsa (RSA with SHA-1 signatures)

=== Host keys (3) ===

/etc/ssh/ssh_host_rsa_key (last modified 2023-11-04)
  RSA 2048-bit  SHA256:/EqCt23YD1l/qoc+0D2kBP6H6jCo3An+wBUshL+LFPY
  [MEDIUM] RSA 2048-bit is below policy minimum of 3072
...
=== authorized_keys (3 file(s), 6 key(s)) ===

svc-backup: /var/lib/svc-backup/.ssh/authorized_keys (2 key(s), last modified 2026-02-17)
  [HIGH] /var/lib/svc-backup/.ssh/authorized_keys is owned by mallory, not svc-backup or root
...
Totals: CRITICAL: 1  HIGH: 3  MEDIUM: 5  LOW: 1  INFO: 2
```

## Run it

The tool is one Python file. It needs nothing but Python 3.10+ and
`ssh-keygen` (package `openssh-client` / `openssh-clients`) — no third-party
dependencies, and no package to install. Copy it to the server and run it as
root. No package is installed and no key file or configuration is touched;
the only thing a run writes is a temporary directory holding a single symlink,
created while fingerprinting a legacy PEM or PKCS#8 private key and removed
immediately afterwards.

```bash
curl -fsSLO https://github.com/seanthegeek/audit-ssh-keys/releases/latest/download/audit-ssh-keys.py
scp audit-ssh-keys.py server:
ssh server sudo python3 audit-ssh-keys.py
```

`releases/latest/download/` always fetches the newest release that is not a
prerelease (the workflow marks any tag containing a letter as a prerelease, so
`latest` never hands out one of those). To pin a specific version, use
`https://github.com/seanthegeek/audit-ssh-keys/releases/download/vX.Y.Z/audit-ssh-keys.py`
instead. Either way, `python3 audit-ssh-keys.py --version` tells you which
version you have — worth recording alongside any report you keep.

Run it as root — other accounts' key files and the host private keys are not
readable otherwise, and `sshd -T` needs root.

```bash
sudo python3 audit-ssh-keys.py            # human-readable report
sudo python3 audit-ssh-keys.py -v         # list every key, not just those with findings
sudo python3 audit-ssh-keys.py --json     # machine-readable, for pipelines and fleet rollups
sudo python3 audit-ssh-keys.py --authorized-keys-changed-within 7   # flag authorized_keys files modified in the last 7 days
```

## Install

For a machine you administer, rather than one you're investigating, installing
from PyPI gets you an `audit-ssh-keys` command that takes exactly the same
options.

```bash
pipx install audit-ssh-keys
# or, from a checkout
pipx install .
```

Then run it as `audit-ssh-keys`, with the same options:

```bash
sudo audit-ssh-keys
```

## What it checks

| Section | Checks |
| ------- | ------ |
| Server configuration | Weak signature algorithms still accepted (`ssh-dss`, SHA-1 `ssh-rsa`, and their certificate forms); `StrictModes no`; `PermitRootLogin yes`; password auth enabled |
| Host keys | Algorithm and size; ownership and mode (`sshd` refuses a root-owned key with group/other permission bits; a key owned by anyone else loads regardless, which is its own problem); a `.pub` file next to the key checked against the key itself; configured-but-missing keys; passphrase-protected keys; missing Ed25519 key; optionally, keys whose file changed inside a window you name (`--host-keys-changed-within`) |
| `authorized_keys` | Every account, every configured path; algorithm and size; what `StrictModes` would reject (the file and every directory above it, up to `$HOME` for a file inside the home directory and otherwise up to `/`, must be owned by the user or root and not group/world-writable); the same key reused across accounts; unrestricted keys on uid-0 accounts; malformed lines; optionally, files changed inside, or untouched for longer than, a window you name (`--authorized-keys-changed-within`, `--authorized-keys-unchanged-for`) |
| Private keys in `~/.ssh` | Algorithm and size; ownership and mode; whether a passphrase is set; a `.pub` file next to the key checked against the key itself |

Every host key, `authorized_keys` file and private key is also reported with
the date it was last modified. The three `DAYS` options in the table turn
that date into a finding; they are off unless you ask for them.

Every finding has a severity (CRITICAL, HIGH, MEDIUM, LOW, INFO). See
[docs/findings.md](docs/findings.md) for what each one means and why it has the
severity it does.

## Documentation

- [Usage](docs/usage.md) — options, exit codes, JSON schema, running without installing, fleet usage
- [Findings reference](docs/findings.md) — every finding, its severity, and remediation
- [How it works](docs/how-it-works.md) — what is read, what is not, known gaps
- [Development](docs/development.md) — running tests, linting, releasing

## Disclaimer

This tool was developed with the assistance of AI coding agents. All code has
been reviewed and tested by a human, but you should review it yourself before
running it on systems you care about. It only reads files and runs `ssh-keygen`
and `sshd -T`; it never modifies keys or configuration.

## License

MIT — see [LICENSE](LICENSE).
