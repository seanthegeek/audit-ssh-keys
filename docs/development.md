# Development

```bash
git clone https://github.com/seanthegeek/audit-ssh-keys
cd audit-ssh-keys
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Checks

Run exactly these, from the repo root, before opening a PR:

```bash
ruff check .
ruff format --check .
pyright
pytest
```

`ruff format .` fixes formatting in place.

## Tests

- Tests generate real keys with `ssh-keygen` into `tmp_path`; nothing key-shaped is committed. Tests that need `ssh-keygen` are skipped if it is not installed.
- Audit functions take an explicit list of `pwd.struct_passwd` entries (`users=`) and explicit config paths / `sshd` binary, so tests build fake accounts under `tmp_path` and never touch the real system.
- A few ownership tests need root (`chown`) and are skipped otherwise; run them locally with `sudo -E pytest` if you touch ownership logic.
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

4. Build the wheel and sdist:

   ```bash
   uvx hatch build
   ```

   (or `python -m build`). Both land in `dist/`.

5. Create the GitHub release, attaching those files:

   ```bash
   gh release create vX.Y.Z --title X.Y.Z --generate-notes dist/*
   ```

   The title has no `v` prefix, per this repo's release rules, even though the tag does.

PyPI publishing is not set up yet.
