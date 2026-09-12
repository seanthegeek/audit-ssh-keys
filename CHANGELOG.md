# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-12

### Added

- Initial release: audits `sshd` host keys, every account's `authorized_keys` (resolved from the effective `AuthorizedKeysFile`), and private keys in `~/.ssh`
- Server-configuration checks for weak accepted signature algorithms, `StrictModes`, `PermitRootLogin`, and password authentication
- Coverage warnings when keys come from `AuthorizedKeysCommand` or `TrustedUserCAKeys`, when `HostKeyAgent` holds the private host keys, or when `AuthorizedKeysFile` mixes `none` with real paths (which OpenSSH's current development code rejects, so a future upgrade may stop `sshd` starting)
- `--json` output for fleet rollups; `-v/--verbose` to list every key including clean ones; `--skip-host`, `--skip-authorized`, `--skip-private`, `--min-rsa-bits`, `--debug`, `--version`; and the opt-in modification-time thresholds `--authorized-keys-unchanged-for`, `--authorized-keys-changed-within` and `--host-keys-changed-within`
- The date each key file was last modified, on each host key, `authorized_keys` file, key entry and private key heading in the text report, and as `last_modified` (`file_last_modified` on an `authorized_keys` entry) in the JSON
- Test suite and docs
- Published on PyPI as `audit-ssh-keys`; the release workflow uploads the wheel and sdist through a PyPI trusted publisher

[0.1.0]: https://github.com/seanthegeek/audit-ssh-keys/releases/tag/v0.1.0
