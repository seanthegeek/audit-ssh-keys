# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial release: audits `sshd` host keys, every account's `authorized_keys` (resolved from the effective `AuthorizedKeysFile`), and private keys in `~/.ssh`
- Server-configuration checks for weak accepted signature algorithms, `StrictModes`, `PermitRootLogin`, and password authentication
- Coverage warnings when keys come from `AuthorizedKeysCommand` or `TrustedUserCAKeys`
- `--json` output for fleet rollups; `-v/--verbose` to list every key including clean ones; `--skip-host`, `--skip-authorized`, `--skip-private`, `--min-rsa-bits`, `--debug`
- Test suite; CI, CodeQL, and release workflows; and docs
