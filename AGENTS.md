# AGENTS.md

## Project overview

`audit-ssh-keys` is a single-purpose, stdlib-only Python CLI that audits every SSH key on a Linux server: the `sshd` host keys, every account's `authorized_keys` (resolved from the *effective* `AuthorizedKeysFile` via `sshd -T`), and private keys in `~/.ssh`. It grades algorithm/size, replicates what `sshd`'s `StrictModes` actually rejects, finds keys reused across accounts, and reports when `sshd` sources keys from somewhere a file audit cannot see. Output is a severity-tagged text report or JSON. It is meant to be run as root, on the box, and to change nothing.

Read `docs/how-it-works.md` before changing any check, and `docs/findings.md` before changing any severity — the severities are reasoned, not arbitrary, and the docs are the contract with users.

## Project-specific rules

- **The tool never modifies anything.** No `chmod`, no `chown`, no rewriting key files, no `--fix` flag. It reads files and runs `ssh-keygen -l` and `sshd -T`. If a feature needs to change the system, it belongs in a different tool.
- **Match `sshd`'s behaviour, not folk wisdom.** Permission checks encode what `sshd` enforces (`secure_filename()`: owner is the user or root; no group/other *write* bits on the file, `~/.ssh`, and `$HOME`). Mode 644/755 is accepted by `sshd` and must not be flagged. Host keys are the exception: `sshd` refuses any group/other bits on them. When in doubt, test against a real `sshd` — `sshd -T` and `ssh-keygen` are cheap to run in a container.
- **Every ssh-keygen call gets `stdin=subprocess.DEVNULL`.** Nothing in this tool may ever block on a passphrase prompt.
- **Do not use `ssh-keygen -y` to detect passphrases.** It refuses world-readable keys — exactly the ones most worth reporting. `private_key_is_encrypted()` inspects the file format instead. Keep it that way.
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
- **Back up the any database before any schema or migration change.** Before running any schema-changing SQL (ALTER TABLE, CREATE/DROP, hand-rolled column rewrites, anything that mutates table shape) against a database, back it up.
- **Project-specific rules belong in AGENTS.md, not in any agent's private memory store.** If you (Claude Code, Cursor, Codex, Aider, anything that has a "save this preference for next time" surface) catch yourself about to write down a rule that's actually about the codebase rather than about working with this particular user, write it here instead. Memory is fine for user-profile facts and tool-use preferences; project rules should be portable across agents.
- **Plain language over jargon.** Comments, docstrings, AGENTS.md, commit messages, PR descriptions, and user-facing docs should describe what the code does in words a non-specialist would understand. Avoid terminology imported from neighboring fields that only loosely applies — e.g., "projection" from relational algebra to describe "the subset of recap_document fields we keep in the local store", or "compaction" / "denormalization" / similar when a plain description works. When a domain term IS the right word (because the code really is implementing that concept, or the reader needs to look it up to understand a library), use it AND a brief in-place gloss the first time it appears. When a term is borrowed loosely, replace it with the literal description. The test is whether a contributor coming into the codebase from a different background would have to stop and search to understand what a term refers to here; when in doubt, prefer the plainer rewrite even if it's a few extra words.
- **Fix underlying bugs, never just patch the data.** A manual SQL update or shell command that corrects ONE row of bad state a database doesn't help other users running the same code, doesn't help future data hitting the same bug, and doesn't survive a fresh checkout. Every observed bug must result in a code change that prevents the bad state from recurring, even when an immediate manual patch is also applied to unblock the operator. The manual patch is the bridge; the code fix is the destination — both happen, never just the bridge.
- **Verify library signatures against the installed version, not memory.** Before calling an unfamiliar function from a third-party library, read the source of the version that is actually installed in the project (the file in `site-packages` or equivalent). Training data and prior conversations are not authoritative — the installed code is.
- **Read official documentation in full before implementing against an unfamiliar API.** Fetch the relevant pages and read them end-to-end, not just the headings. When the docs offer both a quick-reference and a detail page on the same topic, read the detail page — quick-references omit aliases, edge cases, and secondary functions you will need.
- **SDK research order: installed source, then vendor docs, then GitHub issues.** When figuring out how a vendor SDK behaves, the installed SDK's source is the source of truth, vendor documentation is second, GitHub issues are third (for known bugs and undocumented behavior). Third-party blogs, Stack Overflow answers, and AI-generated explainers are not primary evidence — at best they are pointers to one of the three primary sources.
- **Don't catch `Exception` broadly.** Catch only the specific exception types you have a recovery path for. A bare `except Exception:` (or `except:`) hides programming errors that should be loud, makes debugging harder, and disguises broken assumptions as transient failures. Let unexpected exceptions propagate.

## Testing

- **A test named for an exclusive claim must prove both halves.** "Only", "never", and "exactly once" each assert a negative as well as a positive. If the shared test setup can't observe the negative half, build a fresh setup for it instead of substituting a nearby assertion that always passes.
- **Prove a regression test by running it against the unfixed code.** A test written alongside a bug fix must fail when the fix is reverted; otherwise it guards nothing.
- **When testing end-to-end, confirm you are running the edited code.** Running a package from outside the project directory can silently resolve an older installed copy; check the module's file path (or the paths in a traceback) before trusting the result — an old copy can convincingly reproduce the exact bug you are fixing.

## Review discipline

These rules were distilled from real multi-agent review cycles in which defects survived thorough author-side review — in later cycles, a fresh-context diff review as well. Each one names a pattern that self-review reliably misses. Grouped by theme.

### Review prose as prose

A review that only verifies functional correctness (tests pass, files import, types check) sails past exactly the defects a text-first reviewer catches.

- **Whole-file regenerated artifacts put every line in the diff — review them as text, too.** Re-exporting a dashboard definition or other generated document rewrites the entire file, so pre-existing user-facing strings are formally part of the change; a semantic before/after comparison deliberately looks through them. Add a text-level pass over titles, labels, and markdown.
- **Proofread the whole hunk and the *rendered* text, not just the `+`/`-` lines.** Typos one line away from an edit are in your context window and fair game, and wrap points interact with markers and punctuation (a comment marker landing before an issue number, a trailing hyphen, a code span split across lines) — reflow rather than argue the raw text is technically correct.
- **Clean inert config inside hunks the diff already rewrites** — stale entries cost nothing to remove and confuse every later reader; "minimize the diff" is the wrong tiebreaker there, and remains the right one for untouched files.
- **Docstrings and comments are prose surface too — beware dual-use terms.** Words that are both colloquial English and load-bearing technical terms near the code in question ("nested", "index", or "keyword" near a search-engine mapping) pattern-match as true for an author who holds both facts.
- **A plain-type docstring is wrong when `None` is a semantic state.** Documenting optional parameters with bare types is fine while `None` merely means "not provided"; when `None` is a meaningful third state (a sentinel selecting "inherit" or "auto"), document the union type and the sentinel's meaning, reading the entry as a naive caller who doesn't share your context.

### Nothing is pre-verified

Code that *feels* already-reviewed — or exempt from review — has zero review coverage. Five disguises:

- **Moved code.** A "pure move" is a claim about behavior preservation, not an exemption from review — read extractions cold, and be *more* suspicious when a hunk gains callers than when it changes logic.
- **Extracted helpers.** A helper promoted out of a call site inherits none of that site's implicit guarantees: it needs its own eager input validation and its own docstring↔behavior check, even when every current caller happens to be safe.
- **Fixes made during review.** Touching one direction of a paired protocol (`__getstate__`↔`__setstate__`, save↔load, encode↔decode) obligates re-deriving the inverse direction, including version-skew inputs (old data into new code) that no current fixture produces. The review isn't done when the fixes are written.
- **Rewritten code, for coverage.** Rewritten lines are new patch lines even when behavior is intentionally identical — error branches carried over from the old code still need tests now.
- **Mid-incident glue.** Firefighting is not an exemption: before writing new shell/infra code mid-incident, check the file for an existing helper that already does it, and give your own inline code the same scrutiny you'd give a subagent's.

### Check claims against what they range over

The defects that author-side reviews miss are rarely inside one artifact — they are relations between two individually-correct places.

- **When fixing one half of a contract, grep for the other half**: write↔read against the type contract, comment↔declaration, a docstring guarantee↔every statement in its scope, a UI string↔the docs naming it.
- **Count enumerations against the code-defined set they enumerate** — derive the set from the code and count both sides; a reader can't tell an intentional subset from an omission.
- **A quantified claim is an enumeration in disguise, and "pre-existing" triage stops applying when the diff extends its set.** A paragraph asserting something about "all the options above" becomes part of the diff the moment the diff adds options — re-derive the claim against the current diff; don't inherit an earlier pass's "pre-existing, out of scope" label.
- **Build verification fixtures containing what the sample corpus lacks** — optional fields, injected errors, over-the-cap sizes — because an absent field makes the wrong key and the right key behave identically.
- **Update tracking state only after the action it tracks has succeeded.** When code clears a counter, marks something done, or advances a cursor around an action that can fail (a file move, a write, a network call), do the update after the action succeeds — then walk each failure branch and ask what the state means if the action fails right there. Reviews reliably verify that cleanup *exists*; they miss *when* it runs.
- **If something can report failure two ways, handle both ways the same.** A function that signals failure by return value in one configuration and by raised exception in another must run the same cleanup and safety logic on both paths. Find every place that raises, not just every place that returns — and remember that what happens to a raised exception depends on every caller it can propagate through.

### Verify what CI enforces, not a plausible subset

- **Run CI's literal commands from the repo root** — read the workflow file. When repo-wide runs are noisy because of untracked local directories, fix the exclusion in config rather than narrowing the command — a narrowed command is a different check that happens to share a name.
- **Cover CI's gates, not just its commands.** Patch coverage corresponds to no replayable workflow command, so command-replay never asks "does a test execute every new line?" — compare coverage's missing-lines report against the diff before opening a PR.
- **An ad hoc check that matches nothing is broken, not green.** Build one-off verification scripts to fail loudly on zero matches — a filter aimed at the wrong path or key silently produces an empty, passing-looking result. Silence is not success.

### End with a fresh-context review, not a self re-read

The author's "cold re-read" is never cold — it confirms the model the author already holds, which is exactly the blindness a fresh reader doesn't share. Before opening a PR, run a review pass whose reviewer has seen *only* the final diff — no plan, no conversation history, no memory of writing it (a subagent given just the diff, or an external reviewer) — and end it asking "do these hunks agree with *each other*?", not "is each hunk correct?". Triage its findings like any external review: fix what's real, push back with cited reasoning on what isn't. Two limits to design around: a fresh-context reviewer running the same model still shares its priors (convention-compliance can pass for correctness), and some defect classes are only caught by deterministic gates, not by more reading.

## Python Code Style

These standards appply to ALL project Python code **including tests**.

- Formatter/linter: **Ruff**
  - All code must be linted and formatted
- Type annotations use `TypedDict` for structured results
- Supports all currently supported Python versions
- Modern type annotations across the entire project
  - Always use the the latest version of pywright for static type checking
- Testing framework: **pytest**
- Every bit of code should have a test
- Build backend: **hatchling**
- Module-level loggers: `logger = logging.getLogger(__name__)` — one logger per module, named for the module
- Project-defined errors subclass `RuntimeError`, not bare `Exception`, so callers can catch project failures specifically without sweeping in unrelated bugs

## Markdown Style

- All markdown must pass VSCode's default markdownlint config
  - VScode projects must be configured with `"markdownlint.config": {"MD024": false}` to allow for proper changelog headings

## GitHub releases

- Releases are made by version tag not branch
- Version tags should be prefixed with `v`, unless prior tags are not
- Release titles must always exclude the `v` prefix
- For Python projects, wheels and srcbuilds should always be attached
  - Use existing build files **if** they match the release version

## Documentation

The project must be well documented. If existing documentation exists, hollow that convention.

For new projects, do **NOT** use a monolithic readme. Instead, use the readme to provide an overview of the project, and leave specific details in friendly, bite-sized markdown-formatted pages in a `docs` directory.
