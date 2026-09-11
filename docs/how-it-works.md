# How it works

## What it reads

1. **Effective sshd config.** Runs `sshd -T`, which resolves `Include` directives and prints every effective keyword with its final value. If that fails (no `sshd` binary, not root, or the config is broken) it falls back to parsing `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/*.conf` directly, skipping `Match` blocks and taking the first occurrence of each keyword. The fallback cannot see fully-expanded algorithm lists, so those checks are skipped and a coverage warning says so.

   `sshd -T` validates the whole configuration before printing anything, so when it fails, its stderr is itself useful: bad host-key permissions, missing host keys, and syntax errors all show up there. The tool surfaces that text in the coverage warning.

2. **Host keys.** Every `HostKey` directive, or the OpenSSH defaults when none is set. Each is fingerprinted from its `.pub` sibling when present, else from the private key.

3. **authorized_keys.** For every account returned by `getpwall()` (so NSS/LDAP accounts are included when the host resolves them), each `AuthorizedKeysFile` pattern is expanded (`%h`, `%u`, `%U`, `%%`) and every existing file is scanned line by line. Each line is split into options and key material, and the key material is passed to `ssh-keygen -lf -` for type, size, and fingerprint. Per-line invocation is slower than fingerprinting the whole file at once, but it is the only way to keep line numbers accurate when `sshd` would skip a malformed line.

4. **Private keys.** Every regular, non-symlink file directly in each account's `~/.ssh` that begins with a PEM or OpenSSH private-key header. Whether a passphrase is set is decided by inspecting the file (the OpenSSH format embeds the cipher name; PEM uses a `Proc-Type` header; PKCS#8 uses a distinct `BEGIN` line) rather than by asking `ssh-keygen`, because `ssh-keygen` refuses to load a world-readable key — exactly the keys most worth reporting on.

## What it does not read

The report's **coverage warnings** list these when they apply:

- **`AuthorizedKeysCommand`** (sssd, ec2-instance-connect, GitHub-backed helpers, etc.). Keys served by a command are not files and are not audited.
- **`TrustedUserCAKeys`** — certificate-based logins. The CA is a file, but the set of certificates it has signed is not visible from the server.
- **`PubkeyAuthentication no`** — everything in `authorized_keys` is inert.
- **`AuthorizedKeysFile none`** — no files are consulted.

Other things out of scope by design:

- Key *age* — `authorized_keys` carries no timestamp. Compare fingerprints against an inventory if you need this.
- Keys under `~/.ssh` subdirectories, or in locations that are not `~/.ssh` (only host keys and `AuthorizedKeysFile` paths are read from config).
- Weak-entropy detection (the 2008 Debian OpenSSL blocklist). Rare enough now that it is left to `ssh-vulnkey`-style tooling.
- Client-side config (`~/.ssh/config`, `known_hosts`).

## Safety

The tool only reads files. The only external commands it runs are `ssh-keygen -l` (fingerprinting) and `sshd -T` (a config dry-run that does not start a daemon). Nothing is modified. All `ssh-keygen` calls have stdin closed so they can never block on a passphrase prompt.
