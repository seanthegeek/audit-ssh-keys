# AGENTS.md

## Project overview

`audit-ssh-keys` is a single-purpose, stdlib-only Python CLI that audits every SSH key on a Linux server: the `sshd` host keys, every account's `authorized_keys` (resolved from the *effective* `AuthorizedKeysFile` via `sshd -T`), and private keys in `~/.ssh`. It grades algorithm/size, replicates what `sshd`'s `StrictModes` actually rejects, finds keys reused across accounts, and reports when `sshd` sources keys from somewhere a file audit cannot see. Output is a severity-tagged text report or JSON. It is meant to be run as root, on the box, and to change nothing.

Read `docs/how-it-works.md` before changing any check, and `docs/findings.md` before changing any severity — the severities are reasoned, not arbitrary, and the docs are the contract with users.

## Project-specific rules

- **The tool never modifies the system it audits.** No `chmod`, no `chown`, no rewriting key files, no `--fix` flag. It reads files and runs `ssh-keygen -l` and `sshd -T`. If a feature needs to change the system, it belongs in a different tool. The one exception: fingerprinting a private key that has no readable embedded public half (the legacy PEM and PKCS#8 formats) creates a throwaway temporary directory holding a single symlink, so that `ssh-keygen -l` reads the private key itself instead of being silently steered by a stale `.pub` file sitting beside it; no key material is ever copied, and the directory is removed immediately afterward.
- **Match `sshd`'s behaviour, not folk wisdom.** Permission checks encode what `sshd` enforces (`safe_path()` in misc.c, reached through `auth_secure_path()`): after following symlinks, the `authorized_keys` file and every directory above it must be owned by the user or by root and must have no group/other *write* bits. The walk stops once it has checked `$HOME` when the file is inside the home directory, and otherwise goes all the way up to `/`, so a custom `AuthorizedKeysFile` under a world-writable directory such as `/tmp` is rejected outright. Mode 644/755 is accepted by `sshd` and must not be flagged. Host keys are the exception: `sshd` refuses any group/other bits on them. When in doubt, test against a real `sshd` — `sshd -T` and `ssh-keygen` are cheap to run in a container.
- **Every external command gets `stdin=subprocess.DEVNULL` (or an explicit `input=`), and the one call that loads a private half, `ssh-keygen -y`, always gets `-P ""`.** This covers `sshd -T` and the test harness's own subprocess calls too, not just `ssh-keygen`: nothing this tool runs should ever be able to wait on a terminal. Nothing in this tool may ever block on a passphrase prompt. Closing stdin is not enough on its own: `ssh-keygen` asks for passphrases through `/dev/tty`, or through the `SSH_ASKPASS` program when a desktop session is set, so a bare `ssh-keygen -y` on a passphrase-protected (or corrupt) key pops a GUI dialog on the operator's screen. Handing over an empty passphrase with `-P ""` makes it fail immediately instead. This applies to experiments run while developing, too — a stray `ssh-keygen -y` in a test harness has already interrupted a real desktop session; for one-off experiments outside the test suite, also export `SSH_ASKPASS_REQUIRE=never` so a desktop session's askpass program cannot turn a prompt into a dialog box.
- **Do not use `ssh-keygen -y` to detect passphrases.** It refuses world-readable keys — exactly the ones most worth reporting. `private_key_is_encrypted()` inspects the file format instead. Keep it that way. The one permitted `-y` call is `_ssh_can_load_private_key()`, which asks whether `ssh` can load the private half of a key already known to have no passphrase; it runs only when `_ssh_keygen_would_refuse()` says the permission refusal cannot happen, so a refusal never turns into a wrong answer, and it always passes `-P ""`.
- **Probe paths with `_stat_if_present()` and `_is_regular_file()` rather than a bare `Path.is_file()`, `is_dir()` or `exists()`.** Those methods hide a version difference that this tool runs straight into: on Python 3.10 through 3.12 they only swallow missing-path errors (no such file, not a directory, a symlink loop) and *raise* on a permission error, while on 3.13 and later they swallow every OSError and quietly answer "no". The same line therefore crashes on one interpreter and reports a key file as absent on another (43f9001). Decide at each call site what a permission error should mean — usually a LOW "could not stat" finding, never silence. A bare call is acceptable only where the call site already handles OSError and has decided what a permission error means there.
- **Everything read from a key file or an `sshd` config is hostile input, and parsing it must never abort the run.** A number in a key option can be longer than `int()` will parse, which raises above 4300 digits (df00dd9); a file can hold bytes that are not valid text and the run must continue (f8b3195); a key comment can hold terminal control characters (b72a6ef). Every new parser gets a test with an oversized value and a garbage value. This is not a licence to catch broadly (see the `Exception` rule under Conventions): guard the one conversion that can fail and let everything else propagate.
- **Every line of the text report goes through `_out()`.** It passes the text through `_printable()`, which escapes control, format, separator and surrogate characters so that a key comment cannot repaint or rewrite the operator's terminal. New report output must use `_out()`; JSON output does not, because the JSON encoder already escapes those characters.
- **How a file is decoded is a property of the file, not of the operator's locale.** Private-key files are decoded as strict ASCII, because a stray byte makes the key unfingerprintable — `ssh` itself refuses it. `sshd_config` and `authorized_keys` are read as UTF-8 with undecodable bytes replaced, so a bad byte inside a key blob fails that one line while a bad byte in a comment merely displays oddly (f8b3195).
- **When replicating an `sshd` parser, read the actual loop in the OpenSSH source and test its edges.** The edges are where the surprises live: an empty token (the key-option loop in `auth-options.c` has no final `else`, so an unmatched token is rejected only because the character after it is not a comma — which means a leading or doubled comma is skipped and the line is accepted, as a live OpenSSH 10.2 login confirmed; only a comma at the very end of an options-only line is "unexpected end-of-options"), `\"` being the only escape recognised inside an option value, flag names matched by prefix, keywords matched without regard to case, and the `none` and `(null)` values that mean "nothing configured" rather than a filename (8e99a33, b72a6ef). Read the whole loop, not just its error strings: the strings say what is rejected, the control flow says what is quietly accepted.
- **`sshd -T` on its own does not apply `Match` blocks.** It prints the configuration as if no `Match` block matched, and gives no hint that any exist, so each account's `AuthorizedKeysFile` has to come from `sshd -T -C user=<account>` (91c9603). The fallback parser used when `sshd` cannot be run skips `Match` blocks entirely and says so in a coverage warning.
- **The legacy `.pub` fallback is deliberate and narrow.** Only a PEM or PKCS#8 key whose private file cannot be read — because of a passphrase, a corrupt body, `ssh-keygen` refusing its permissions, or a temporary directory or symlink that could not be created — is reported from the `.pub` file beside it. A key in the current OpenSSH format never is, because its public half is stored unencrypted inside the private file. In the narrow fallback case a stale `.pub` cannot be detected, and that is an accepted limit, not an oversight (c7a616b).
- **`DEFAULT_HOST_KEYS` keeps `/etc/ssh/ssh_host_dsa_key` on purpose.** That list is only consulted when `sshd -T` cannot be run, which is exactly where a pre-7.0 `sshd` — the versions that loaded a DSA host key by default — ends up. Do not drop the entry on the strength of a modern default list.
- **OpenSSH research order: the installed binaries, then the OpenSSH source, then the man pages.** First test the `sshd` and `ssh-keygen` on the box (`sshd -T -f`, `ssh-keygen -l`, a throwaway `authorized_keys`). Then read the OpenSSH source for that version — `servconf.c`, `auth-options.c`, `auth2-pubkeyfile.c`, `safe_path()` in `misc.c`, `sshkey_perm_ok()` in `authfile.c`. The man pages come third. Blog posts and forum answers are pointers to those sources, never evidence on their own. Record the OpenSSH version a behaviour was verified against in the comment or the docs row that describes it.
- **File-level findings are separate from key-level findings.** A permission problem on a file with zero valid keys, or with a comment on line 1, must still be reported. Do not attach file findings to a key.
- **Keep the stdlib-only, single-module shape.** No third-party runtime dependencies; the tool is copied to hosts that may have nothing but `python3` and `openssh-client`. Keep `src/audit_ssh_keys/audit.py` as the one module unless it becomes genuinely unwieldy.
- **Fingerprint per line, not per file.** `ssh-keygen -lf <file>` on an `authorized_keys` file skips malformed lines silently, which breaks line numbers. Per-line invocation is intentional.
- **`--min-rsa-bits` cannot lower the 2048 floor.** RSA below 2048 is CRITICAL regardless of the option.
- **Audit functions take injectable inputs** (`users=`, `config_paths=`, `sshd_bin=`) so tests never touch the real system. Preserve that when adding checks.
- **Tests generate keys; they never commit them.** `.gitignore` blocks `id_*`, `ssh_host_*`, `*.pem`. Fixtures use `ssh-keygen` into `tmp_path`.
- **A new finding needs three things:** the check, a test that proves it fires and a test that proves it does not fire on the clean case, and a row in `docs/findings.md` with severity, why, and fix.

## Conventions

These rules apply to anyone — human or agent — making changes to this repo. They are intentionally checked in (rather than living in any one agent's private scratch memory) so that every collaborator picks them up the same way.

- **Wait for explicit commit AND push permission on the default branch — these are separate grants.** Finish the implementation, run the tests, summarize the diff, then **stop and ask**. The author decides when a change is ready to land; auto-committing makes review noisier and harder to reverse. "Commit this" mid-session counts as permission for that one commit, not a standing grant — and crucially, permission to commit is NOT permission to push. Pushing publishes the change to the remote where collaborators / CI / production deploys can pick it up, and is much harder to walk back than a local commit. Wait for an explicit "push it" before `git push`. If the prior commit was itself unauthorized, do NOT push it to "tidy up" — surface the situation and let the author decide whether to keep, amend, or reset.
- **Self-test before every `git commit`:** has the author typed "commit" (or an unambiguous equivalent — "ok to commit", "commit this", "commit and push") in a present-tense imperative since your last commit? If no, **ask**. Conditional phrasings like "if everything works we can push" or "we could commit this" or "if it looks good ..." are NOT authorizations — they are plans you must confirm before acting on. Treat the literal text of the user's last message as the source of truth, not your own interpretation of where the conversation is going.
  - **Self-test before every `git push`:** has the author typed "push" since your last push? Same rule. Permission to commit is NEVER permission to push.
  - **Exception — branches you created in-session** When you have explicitly created a feature branch yourself (e.g. `git checkout -b feat/something`) in that session, commit and push to THAT branch freely without per-step permission. The entire branch is reviewed at PR-open, so the per-commit gate adds review noise without adding safety. The exception is scoped to branches Claude created in the current session; it does NOT extend to `main`, to other long-lived branches, or to branches the author created.
- **Project-specific rules belong in AGENTS.md, not in any agent's private memory store.** If you (Claude Code, Cursor, Codex, Aider, anything that has a "save this preference for next time" surface) catch yourself about to write down a rule that's actually about the codebase rather than about working with this particular user, write it here instead. Memory is fine for user-profile facts and tool-use preferences; project rules should be portable across agents.
- **Plain language over jargon.** Comments, docstrings, AGENTS.md, commit messages, PR descriptions, and user-facing docs should describe what the code does in words a non-specialist would understand. Avoid borrowed terms that only loosely apply — write "the public half stored inside the private key file" rather than "the embedded SPKI". When a term IS the right word — because the code really implements that idea, or because the reader has to look it up to follow `sshd` — use it and gloss it in place the first time it appears: "the `none` sentinel (a value that means *this entry names no file*, not a filename)". The test is whether a contributor arriving from a different background would have to stop and search to understand what a term refers to here; when in doubt, prefer the plainer rewrite even if it is a few extra words.
- **Don't catch `Exception` broadly.** Catch only the specific exception types you have a recovery path for. A bare `except Exception:` (or `except:`) hides programming errors that should be loud, makes debugging harder, and disguises broken assumptions as transient failures. Let unexpected exceptions propagate.

## Testing

- **A test named for an exclusive claim must prove both halves.** "Only", "never", and "exactly once" each assert a negative as well as a positive. If the shared test setup can't observe the negative half, build a fresh setup for it instead of substituting a nearby assertion that always passes.
- **Prove a regression test by running it against the unfixed code.** A test written alongside a bug fix must fail when the fix is reverted; otherwise it guards nothing. The routine: `git stash push -- src/`, run the new tests and check that the ones covering the bug fail, then `git stash pop` and watch them pass.
- **Tests must not depend on the host's account database, the uid the suite runs as, or the umask.** Monkeypatch `audit.pwd.getpwnam` and `audit.pwd.getpwuid` when a test needs an account that does not exist (see `tests/test_config.py`), give fake accounts `USER_UID` and create their directories with `mkdir_clean()` (both in `tests/conftest.py`), and confirm the suite is green under both `umask 002` and `umask 022` (91c9603, 96ebaa0).
- **When testing end-to-end, confirm you are running the edited code.** Running a package from outside the project directory can silently resolve an older installed copy; check the module's file path (or the paths in a traceback) before trusting the result — an old copy can convincingly reproduce the exact bug you are fixing.
- **Docs move with behaviour, in the same commit.** The findings row required by "A new finding needs three things" above is one case of a general rule: a changed check updates `docs/how-it-works.md`, and a changed or added finding or severity updates `docs/findings.md`, in the commit that changes the code — not in a follow-up.

## Review discipline

These rules were distilled from real multi-agent review cycles in which defects survived thorough author-side review — in later cycles, a fresh-context diff review as well. Each one names a pattern that self-review reliably misses. Grouped by theme.

### Review prose as prose

A review that only verifies functional correctness (tests pass, files import, types check) sails past exactly the defects a text-first reviewer catches.

- **A rewritten table puts every row in the diff — review the rows as text, too.** Adding a column to one of the `docs/findings.md` tables, or re-wrapping it, rewrites rows that nobody meant to change, so wording written months ago is formally part of this change; a semantic before/after comparison deliberately looks through it. Add a text-level pass over every column, the Why column most of all.
- **Proofread the whole hunk and the *rendered* text, not just the `+`/`-` lines.** Typos one line away from an edit are in your context window and fair game, and wrap points interact with markers and punctuation (a comment marker landing before an issue number, a trailing hyphen, a code span split across lines) — reflow rather than argue the raw text is technically correct.
- **Clean inert config inside hunks the diff already rewrites** — stale entries cost nothing to remove and confuse every later reader; "minimize the diff" is the wrong tiebreaker there, and remains the right one for untouched files.
- **Docstrings and comments are prose surface too — beware dual-use words.** Next to `sshd` code, ordinary English words also name specific behaviour: "reject" (does `sshd` refuse the key, refuse the file, or refuse the login?), "accessible" (readable by other users, as in the `world-accessible` finding, or merely reachable by this tool?), "default" (OpenSSH's compiled-in default, or this tool's `DEFAULT_HOST_KEYS` fallback list?), "none" (absence, or the literal `none` keyword). A sentence using one loosely reads as true to an author who holds both meanings at once. Say which one you mean.
- **A plain-type docstring is wrong when `None` is a meaningful state.** Documenting an optional parameter with a bare type is fine while `None` only means "not provided"; when `None` is a third state with its own meaning — `PrivateKeyFinding.encrypted` being `None` for "could not determine", not "no passphrase" — document the union type and what the `None` stands for, reading the entry as a caller who does not share your context.

### Nothing is pre-verified

Code that *feels* already-reviewed — or exempt from review — has zero review coverage. Four disguises:

- **Moved code.** A "pure move" is a claim about behavior preservation, not an exemption from review — read extractions cold, and be *more* suspicious when a hunk gains callers than when it changes logic.
- **Extracted helpers.** A helper promoted out of a call site inherits none of that site's implicit guarantees: it needs its own eager input validation and its own docstring↔behavior check, even when every current caller happens to be safe.
- **Fixes made during review.** Touching one direction of a paired protocol (parse↔report, encode↔decode, the check and the `docs/findings.md` row that describes it) obligates re-deriving the other direction, including inputs no current fixture produces. The review isn't done when the fixes are written.
- **Rewritten code, for coverage.** Rewritten lines are new patch lines even when behavior is intentionally identical — error branches carried over from the old code still need tests now.

### Check claims against what they range over

The defects that author-side reviews miss are rarely inside one artifact — they are relations between two individually-correct places.

- **When fixing one half of a contract, grep for the other half**: the check↔the `docs/findings.md` row naming its severity, a comment↔the code it describes, a docstring guarantee↔every statement in its scope, a report string↔the docs quoting it.
- **Count enumerations against the code-defined set they enumerate** — derive the set from the code and count both sides. When docs list the host key paths, the severities, or the triggers for one finding, a reader cannot tell an intentional subset from an omission.
- **A quantified claim is an enumeration in disguise, and "pre-existing" triage stops applying when the diff extends its set.** A sentence asserting something about "every finding above" becomes part of the diff the moment the diff adds a finding — re-derive the claim against the current diff; don't inherit an earlier pass's "pre-existing, out of scope" label.
- **Build test fixtures containing what the usual ones lack** — a key with no `.pub` sibling, a comment full of control characters, a number too long for `int()`, a file the process cannot read — because an absent case makes a wrong check and a right check behave identically.
- **Update tracking state only after the action it tracks has succeeded.** When code clears a counter, marks something done, or advances a cursor around an action that can fail (a temporary directory removed, a file read, a subprocess run), do the update after the action succeeds — then walk each failure branch and ask what the state means if the action fails right there. Reviews reliably verify that cleanup *exists*; they miss *when* it runs.
- **If something can report failure two ways, handle both ways the same.** A helper that signals failure by return value in one configuration and by raised exception in another must run the same cleanup and safety logic on both paths. Find every place that raises, not just every place that returns — and remember that what happens to a raised exception depends on every caller it can propagate through.

### Run the parity claim, don't read it

A comment saying the code now matches `sshd` is really two claims: one about what `sshd` does, and one about what the Python line does. A reviewer who knows OpenSSH checks the first, finds it right, and lets the second stand — the code reads as idiomatic and the comment above it is true. Three defects reached a late review that way in a single cycle, every one of them a standard-library default that nobody executed:

- **`path.read_text()` reads in universal-newline mode**, turning a bare `\r` into `\n` before anything else sees it. A hunk that changed `.splitlines()` to `.split("\n")` to match `getline()` therefore changed nothing at all: a carriage return inside a `Banner` value still began a second directive. The repair is to open the file with `newline="\n"`; the lesson is that the parity claim was read and never run.
- **`str.strip()` removes Unicode whitespace**, while `sshd` removes only its own ASCII set (`" \t\r"` in front, `WHITESPACE " \t\r\n"` plus a form feed behind). A configuration value ending in a non-breaking space was quietly shortened here and kept by `sshd`.
- **`readline(n)` counts the carriage return of a CRLF ending**, so a line of exactly the cap followed by `\r\n` came back one character too long and a valid key was thrown away.

When a hunk claims to match an external system, write the one input that tells the two behaviours apart and run it. Reading the line and nodding at the comment is not the check. Treat every standard-library call in such a hunk the same way: look up what its default arguments actually do rather than what its name suggests, because a wrong default and a right one read identically.

This class of defect survives a same-model fresh-context review, which shares the very priors that made the code look correct when it was written. It is caught by execution, or by a reviewer built differently — all three above were found by a line-level reviewer after two semantic reviews had passed them.

### Verify what CI enforces, not a plausible subset

- **Run the checks in `docs/development.md` from the repo root**, all of them, exactly as written; once a workflow file exists, read it and run its literal commands rather than a plausible subset. When a repo-wide run is noisy because of untracked local directories, fix the exclusion in the tool's config rather than narrowing the command — a narrowed command is a different check that happens to share a name.
- **Cover CI's gates, not just its commands.** A gate such as patch coverage corresponds to no replayable command, so command-replay never asks "does a test execute every new line?" — once CI enforces one, compare its report (coverage's missing lines against the diff) before opening a PR instead of assuming the commands alone cover it.
- **An ad hoc check that matches nothing is broken, not green.** Build one-off verification scripts to fail loudly on zero matches — a filter aimed at the wrong path or key silently produces an empty, passing-looking result. Silence is not success.

### End with a fresh-context review, not a self re-read

The author's "cold re-read" is never cold — it confirms the model the author already holds, which is exactly the blindness a fresh reader doesn't share. Before opening a PR, run a review pass whose reviewer has seen *only* the final diff — no plan, no conversation history, no memory of writing it (a subagent given just the diff, or an external reviewer) — and end it asking "do these hunks agree with *each other*?", not "is each hunk correct?". Triage its findings like any external review: fix what's real, push back with cited reasoning on what isn't. Two limits to design around: a fresh-context reviewer running the same model still shares its priors (convention-compliance can pass for correctness), and some defect classes are only caught by deterministic gates, not by more reading.

## Pull request review

- **Treat every review comment as a hypothesis, not a defect report.** PRs here get a GitHub Copilot review, and some of its claims across PR #1 were wrong — for example that the DSA host key default should go, and that `sshd` rejects an empty key option. Verify each claim against the OpenSSH source or a real `sshd` before changing any code, and keep the evidence for the reply. Read the earlier threads before acting on a repeated claim: the empty-option finding was refuted with a live login in one round and then wrongly "fixed" from a source reading in a later one (df00dd9, which had to be reverted), because nobody re-read the refutation.
- **Reply to every inline comment individually.** Either "Fixed in `<hash>`" naming the tests that now cover it, or a pushback stating the evidence and why the code is right as written. Re-request the review only when the author asks for it.
- **Low-confidence comments are visible only in the GitHub web UI.** The API reports zero comments for them, so a clean `gh` fetch does not mean a clean review. The review body's summary sentence names the topics; work out the concrete claim from it and verify it, or ask the author to paste the items in. Inline comments are authored by `Copilot`; the reviews themselves, and their body text, by `copilot-pull-request-reviewer[bot]`.

## Python Code Style

These standards apply to ALL project Python code **including tests**.

- Formatter/linter: **Ruff**
  - All code must be linted and formatted
- Structured results are `dataclass`es (this project's findings and report; `dataclasses.asdict()` produces the JSON) or `TypedDict`s when a plain dict shape is required
- Supports all currently supported Python versions
- Modern type annotations across the entire project
  - Always use the latest version of pyright for static type checking
- Testing framework: **pytest**
- Every bit of code should have a test
- Build backend: **hatchling**
- Module-level loggers: `logger = logging.getLogger(__name__)` — one logger per module, named for the module
- Project-defined errors subclass `RuntimeError`, not bare `Exception`, so callers can catch project failures specifically without sweeping in unrelated bugs

## Markdown Style

- All markdown must pass VS Code's default markdownlint config
  - VS Code projects must be configured with `"markdownlint.config": {"MD024": false}` to allow for proper changelog headings

## GitHub releases

- Releases are made by version tag not branch
- Version tags should be prefixed with `v`, unless prior tags are not
- Release titles must always exclude the `v` prefix
- For Python projects, wheels and source distributions (sdists) should always be attached
  - Use existing build files **if** they match the release version

## Documentation

The project must be well documented. If existing documentation exists, follow that convention.

For new projects, do **NOT** use a monolithic readme. Instead, use the readme to provide an overview of the project, and leave specific details in friendly, bite-sized markdown-formatted pages in a `docs` directory.
