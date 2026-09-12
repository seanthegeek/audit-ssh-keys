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
$ sudo audit-ssh-keys
sshd config source: sshd -T

=== Server configuration ===
  [MEDIUM] PubkeyAcceptedAlgorithms accepts ssh-rsa (RSA with SHA-1 signatures)

=== Host keys (3) ===

/etc/ssh/ssh_host_rsa_key
  RSA 2048-bit  SHA256:/EqCt23YD1l/qoc+0D2kBP6H6jCo3An+wBUshL+LFPY
  [MEDIUM] RSA 2048-bit is below policy minimum of 3072
...
=== authorized_keys (3 file(s), 6 key(s)) ===

svc-backup: /var/lib/svc-backup/.ssh/authorized_keys (2 key(s))
  [HIGH] /var/lib/svc-backup/.ssh/authorized_keys is owned by mallory, not svc-backup or root
...
Totals: CRITICAL: 1  HIGH: 3  MEDIUM: 5  LOW: 1  INFO: 2
```

## Install

Requires Python 3.10+ and `ssh-keygen` (package `openssh-client` / `openssh-clients`).
No third-party Python dependencies.

```bash
pipx install audit-ssh-keys
# or, from a checkout
pipx install .
```

Run it as root — other accounts' key files and the host private keys are not
readable otherwise, and `sshd -T` needs root.

```bash
sudo audit-ssh-keys            # human-readable report
sudo audit-ssh-keys -v         # list every key, not just those with findings
sudo audit-ssh-keys --json     # machine-readable, for pipelines and fleet rollups
```

## What it checks

| Section | Checks |
| ------- | ------ |
| Server configuration | Weak signature algorithms still accepted (`ssh-dss`, SHA-1 `ssh-rsa`); `StrictModes no`; `PermitRootLogin yes`; password auth enabled |
| Host keys | Algorithm and size; ownership and mode (`sshd` refuses a root-owned key with group/other permission bits; a key owned by anyone else loads regardless, which is its own problem); a `.pub` file next to the key checked against the key itself; configured-but-missing keys; passphrase-protected keys; missing Ed25519 key |
| `authorized_keys` | Every account, every configured path; algorithm and size; what `StrictModes` would reject (the file and every directory above it, up to `$HOME` for a file inside the home directory and otherwise up to `/`, must be owned by the user or root and not group/world-writable); the same key reused across accounts; unrestricted keys on uid-0 accounts; malformed lines |
| Private keys in `~/.ssh` | Algorithm and size; ownership and mode; whether a passphrase is set; a `.pub` file next to the key checked against the key itself |

Every finding has a severity (CRITICAL, HIGH, MEDIUM, LOW, INFO). See
[docs/findings.md](docs/findings.md) for what each one means and why it has the
severity it does.

## Documentation

- [Usage](docs/usage.md) — options, exit codes, JSON schema, fleet usage
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
