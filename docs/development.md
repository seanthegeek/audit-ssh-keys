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

CI (`.github/workflows/ci.yml`) runs the first three commands unchanged, and
`pytest` with coverage (`pytest --cov=audit_ssh_keys --cov-report=term-missing
--cov-report=xml`) on Python 3.10 through 3.14, on every pull request and every
push to `main`. It also lints Markdown and runs the root-only tests under
`sudo` in a separate job. The release workflow runs the four commands exactly
as written above.

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

1. Add a `## [X.Y.Z] - YYYY-MM-DD` heading to `CHANGELOG.md` above the
   previous release's, brackets included — that is Keep a Changelog's form, and
   the release workflow greps for exactly `## [X.Y.Z]` and stops if it is
   missing — and list the changes under it. Add the matching
   `[X.Y.Z]: https://github.com/seanthegeek/audit-ssh-keys/releases/tag/vX.Y.Z`
   link definition at the end of the file.
2. Bump `__version__` in `src/audit_ssh_keys/__init__.py`.
3. Commit, then tag and push:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

Pushing the tag runs the release workflow
(`.github/workflows/release.yml`), which checks the tag against
`__version__` and the changelog heading, runs the checks, builds the wheel and
sdist, checks that `dist/` holds exactly one of each, uploads both to PyPI, and
creates the GitHub release titled without the `v` with the same two files
attached.

### If the workflow fails after the PyPI upload

Only the steps after the upload can be redone by hand, and the section below
says how to tell which side of it a failure landed on. A failure before or
during the upload is fixed by fixing the cause and re-running the job — there
is no manual upload path.

Everything after the upload is one step: creating the GitHub release. Build the
same two files locally:

```bash
uvx hatch build
```

(or `python -m build`). Both land in `dist/`. Then create the release,
attaching them:

```bash
gh release create vX.Y.Z --title X.Y.Z --generate-notes dist/*
```

The title has no `v` prefix, per this repo's release rules, even though the tag does.

### How PyPI publishing works

PyPI is published through a trusted publisher, so no API token is stored
anywhere: the project is registered on pypi.org against this repository and the
`release.yml` workflow file, and the job's OIDC token is what proves who it is.
That registration names no environment, so the release job must not declare one
— PyPI rejects the token if the two disagree.

The upload runs before the GitHub release is created, because PyPI never
accepts the same version twice. If the upload fails, nothing was uploaded: fix
the cause and re-run the failed job from the Actions tab, leaving the tag where
it is. If the upload succeeded and a later step failed, PyPI already has the
files and only the GitHub release still needs creating, by hand as above.

There is no manual upload path — that is why the by-hand steps above stop at
the GitHub release. A release whose files have to change gets a new version
number.
