# Usage

```bash
sudo audit-ssh-keys [OPTIONS]
```

## Options

| Option | Effect |
| ------ | ------ |
| `--json` | Emit the full report as JSON instead of the human-readable text |
| `--min-rsa-bits N` | RSA keys smaller than `N` bits are flagged MEDIUM (default 3072). RSA below 2048 is always CRITICAL; this option cannot lower that floor |
| `--authorized-keys-unchanged-for DAYS` | Flag LOW every `authorized_keys` file that holds at least one key `sshd` would match and has not been modified in `DAYS` days. Off unless given |
| `--authorized-keys-changed-within DAYS` | Flag MEDIUM every `authorized_keys` file modified within the last `DAYS` days, including one the tool cannot read. Off unless given |
| `--host-keys-changed-within DAYS` | Flag MEDIUM every host key file modified within the last `DAYS` days. Off unless given |
| `--skip-host` | Skip host-key checks |
| `--skip-authorized` | Skip `authorized_keys` checks |
| `--skip-private` | Skip `~/.ssh` private-key checks |
| `-v`, `--verbose` | List every host key, `authorized_keys` entry, and private key — not just those with findings. Entries are grouped by file in line order, with `ok` on clean ones |
| `--debug` | Debug logging to stderr (for example, the raw `sshd -T` failure text) |
| `--version` | Print the version and exit |

## Why root

- Other accounts' `authorized_keys` and private keys are usually mode 600.
- Host private keys are root-only.
- `sshd -T` refuses to run without root, and it is how the tool learns the *effective* configuration (custom `AuthorizedKeysFile`, `HostKey` list, accepted algorithms) rather than guessing from a partial parse of `sshd_config`.

Without root the tool still runs, but only over files the invoking user can read, and it falls back to parsing `sshd_config` directly. The report header shows which source was used.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Audit ran (findings or not — see the report) |
| 2 | Audit could not run at all (`ssh-keygen` missing), or the command line was rejected (an unknown option, or a `DAYS` value that is not a whole number of at least 1) |

The exit code does not reflect findings, so the tool is safe to run from cron or a config-management "gather facts" step. To gate on findings, use `--json` and inspect the severities.

## JSON output

`--json` prints one object with these top-level keys:

| Key | Contents |
| --- | -------- |
| `config_source` | `"sshd -T"` or `"parsed sshd_config (sshd -T unavailable)"` |
| `effective_authorized_keys_file` | The global `AuthorizedKeysFile` patterns. An account whose `Match` block moves the file is still scanned at the moved location (see `authorized_key_files`), but that override is not reflected here |
| `coverage_warnings` | Things the audit could not see (see [How it works](how-it-works.md)) |
| `server_config_issues` | Findings about `sshd` settings |
| `host_keys` | One entry per host key: `path`, `key_type`, `bits`, `fingerprint`, `issues`, `last_modified` |
| `authorized_key_files` | One entry per file: `user`, `file_path`, `key_count`, `issues`, `last_modified` |
| `authorized_keys` | One entry per key: `user`, `file_path`, `line_number`, `key_type`, `bits`, `fingerprint`, `comment`, `options`, `issues`, `file_last_modified` |
| `duplicate_authorized_keys` | `{fingerprint: ["user path:line", ...]}` for keys authorised in more than one place |
| `private_keys` | One entry per private key: `user`, `path`, `key_type`, `bits`, `fingerprint`, `encrypted` (`true`, `false`, or `null` when the file format was not recognised), `issues`, `last_modified` |

Every `issues` entry is `{"severity": "...", "message": "..."}`.

Every last-modified date is the file's modification time as `YYYY-MM-DD` in the
server's local time zone, so it matches what `ls -l` shows on the same host, and
is `null` when there is no date to report — the file is not there, it could not
be stat'd, or the entry names no file at all (a `(none)` host-key placeholder).
On a key entry the field is named `file_last_modified` because it is the date of
the file the line sits in: an `authorized_keys` file carries no per-key
timestamp, so it says when the file changed, not when that key was added.

Fingerprints are SHA256, as printed by `ssh-keygen -l`, so they can be joined against other tooling and across hosts.

## Fleet use

The tool is stdlib-only, so there is no install step required to run it on a host. Three ways to do that:

- Copy the whole `src/audit_ssh_keys/` directory to the host and run `python3 -m audit_ssh_keys` from the directory that contains it.
- Copy just `audit.py` (it has no other files it depends on) and run `python3 audit.py`. Run this way, `--version` reports `unknown` because the package's version file was not copied along with it.
- Install the wheel (`pip install audit-ssh-keys`) and use the `audit-ssh-keys` console script.

A typical rollup:

```bash
for h in host1 host2 host3; do
  ssh "$h" sudo audit-ssh-keys --json > "reports/$h.json"
done
jq -r '.authorized_keys[] | select(.issues[]?.severity == "CRITICAL") | "\(.user) \(.file_path):\(.line_number) \(.fingerprint) \(.file_last_modified)"' reports/*.json
```

Cross-host key reuse is a natural next step: concatenate the `authorized_keys` arrays and group by `fingerprint`.
