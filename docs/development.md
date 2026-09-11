# Development

```bash
git clone https://github.com/seanthegeek/audit-ssh-keys
cd audit-ssh-keys
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Checks

CI runs exactly these, from the repo root, on every supported Python version:

```bash
ruff check .
ruff format --check .
pyright
pytest
```

Run them all before opening a PR. `ruff format .` fixes formatting in place.

CodeQL (`.github/workflows/codeql.yml`) also runs on every push to `main` and every PR, with the `security-extended` query pack, and weekly on a schedule. It has no local equivalent; results appear under the repository's Security → Code scanning tab and as PR annotations.

## Tests

- Tests generate real keys with `ssh-keygen` into `tmp_path`; nothing key-shaped is committed. Tests that need `ssh-keygen` are skipped if it is not installed.
- Audit functions take an explicit list of `pwd.struct_passwd` entries (`users=`) and explicit config paths / `sshd` binary, so tests build fake accounts under `tmp_path` and never touch the real system.
- A few ownership tests need root (`chown`) and are skipped otherwise. They run in CI, where the runner is not root, only when a root-capable job is added; run them locally with `sudo -E pytest` if you touch ownership logic.
- The test uid helper `USER_UID` is `os.getuid()` or `1000` when running as root, because files the suite creates are owned by the real uid and `sshd` accepts root-owned files for any account.

## Layout

```text
src/audit_ssh_keys/
  __init__.py   version
  __main__.py   python -m entry point
  audit.py      everything else, in sections: config, ssh-keygen helpers,
                parsing, grading, the three audit sections, output, CLI
tests/
  conftest.py   key-generation and fake-passwd fixtures
  test_parsing.py   pure functions (no filesystem, no ssh-keygen)
  test_config.py    sshd config reading and server-setting grading
  test_audit.py     permission checks and the three audit sections
docs/
```

## Releasing

1. Update `CHANGELOG.md` (move Unreleased to a dated version heading).
2. Bump `__version__` in `src/audit_ssh_keys/__init__.py`.
3. Commit, then tag and push:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

The `Release` workflow (`.github/workflows/release.yml`) does the rest: it refuses to run if the tag does not match `__version__`, re-runs lint/type-check/tests, builds the wheel and sdist, creates the GitHub release titled `X.Y.Z` (no `v`) with both files attached and auto-generated notes, and publishes to PyPI.

PyPI publishing uses [trusted publishing](https://docs.pypi.org/trusted-publishers/) — no API token is stored. One-time setup: on PyPI, add a trusted publisher for this repository with workflow `release.yml` and environment `pypi`; on GitHub, create an environment named `pypi` (optionally with required reviewers so a tag push cannot publish without a human click). Until that is configured, the `pypi` job fails while the GitHub release still succeeds.
