# Findings reference

Every finding has a severity. The scale is about *what an attacker gets* or *what silently stops working*, not about how hard the fix is.

| Severity | Meaning |
| -------- | ------- |
| CRITICAL | Broken cryptography or key material readable by anyone on the box |
| HIGH | Something `sshd` itself refuses, or that lets another local account inject or use a key |
| MEDIUM | Below current policy but not broken today |
| LOW | Hygiene, or something the tool could not fully check |
| INFO | Worth knowing; no action required by default |

## Server configuration

| Finding | Severity | Why | Fix |
| ------- | -------- | --- | --- |
| `*Algorithms accepts ssh-dss` | MEDIUM | DSA signatures; 1024-bit only, removed from OpenSSH defaults | Remove `ssh-dss` from `HostKeyAlgorithms` / `PubkeyAcceptedAlgorithms` / `CASignatureAlgorithms` |
| `*Algorithms accepts ssh-rsa` | MEDIUM | `ssh-rsa` is RSA with SHA-1 signatures (the key itself is fine; the signature scheme is not). Disabled by default since OpenSSH 8.8 | Remove `ssh-rsa`; RSA keys keep working via `rsa-sha2-256`/`rsa-sha2-512` |
| `StrictModes is 'no'` | MEDIUM | `sshd` will read key files another account can write to | Set `StrictModes yes` and fix whatever permission problem prompted turning it off |
| `PermitRootLogin is 'yes'` | MEDIUM | Permits password-based login as root when `PasswordAuthentication` is enabled | `PermitRootLogin prohibit-password` (or `no`) |
| `PasswordAuthentication is 'yes'` | INFO | Keys are not the only way in | Consider `PasswordAuthentication no` once all users have keys |

Algorithm checks only run when `sshd -T` succeeds, because only it prints the fully expanded effective lists.

## Host keys

| Finding | Severity | Why | Fix |
| ------- | -------- | --- | --- |
| `RSA N-bit is below 2048` | CRITICAL | Factoring risk | `ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key`; clients will see a host-key change |
| `DSA key` | HIGH | Deprecated; modern clients will not accept it | Delete the key and its `HostKey` line |
| `RSA N-bit is below policy minimum` | MEDIUM | Below `--min-rsa-bits` | Regenerate at 3072+ or 4096 |
| `world-accessible private key` | CRITICAL | Any local user can impersonate the server. `sshd` also refuses to load it | `chmod 600` |
| `group-accessible private key` | HIGH | `sshd` refuses to load it ("UNPROTECTED PRIVATE KEY FILE") | `chmod 600` |
| `owned by X, expected root` | HIGH | `sshd` refuses to load it | `chown root:root` |
| `configured HostKey does not exist` | LOW | `sshd` logs an error at start; harmless if another key is present | Remove the line or `ssh-keygen -A` |
| `host key is passphrase-protected` | LOW | `sshd` cannot load it at boot | Regenerate without a passphrase |
| `<name>.pub does not match this private key` | LOW | The public file next to the key is stale or belongs to a different key, so anything copied out of it — into an `authorized_keys` file, a config-management repo, a `known_hosts` entry — authorises the wrong key | Regenerate it: `ssh-keygen -y -f <key> > <key>.pub` |
| `no Ed25519 host key present` | LOW | Ed25519 is the current best-practice host key | `ssh-keygen -A` |
| `could not fingerprint host key` | LOW | The key could not be fingerprinted: a passphrase-protected key in the old PEM format with no `.pub` file, a corrupt or truncated key body in the current OpenSSH format (reported this way even when a `.pub` file is present, since a corrupt file says nothing about which key it was), or a current-format key whose private half `ssh`'s own loader cannot load — mismatched check integers, private fields that do not deserialize, bad padding, or a body mangled in transit (CRLF line endings, indentation). Its algorithm and size were not graded, but its ownership, permissions, and passphrase status are still checked and reported normally | Write the public file (`ssh-keygen -y -f <key> > <key>.pub`) or convert the key to the current format with `ssh-keygen -p -o -f <key>`; for a current-format key `ssh` itself cannot load, regenerate the key (delete the file and run `ssh-keygen -A`) and expect every client to see a changed host key |

## authorized_keys — file level

| Finding | Severity | Why | Fix |
| ------- | -------- | --- | --- |
| `<file/dir/home> is group/world-writable` | HIGH | With `StrictModes yes` (default) `sshd` ignores the file and the account's keys silently stop working. With `StrictModes no` another account can add keys | `chmod g-w,o-w` on the offending path |
| `<path> is owned by X, not <user> or root` | HIGH | Same as above; `sshd` requires the user or root to own the whole path | `chown` |
| `line N: unparseable entry` | LOW | `sshd` skips it; usually a corrupted paste | Remove or re-add the key |
| `line N: bad key options (...)` | LOW | `sshd` refuses the whole line when its options do not parse, so the key on it grants nothing while the file still reads as if it authorised someone. Usually a typo in an option name | Correct the option; the `AUTHORIZED_KEYS FILE FORMAT` section of `sshd(8)` lists every option `sshd` accepts |
| `could not resolve` / `could not stat` / `could not read` | LOW | Tool could not check it. This is what a non-root run reports for another account's files it cannot even stat, rather than silently treating them as absent | Run as root |

The tool follows any symbolic links, then checks the file and every directory above it, stopping once it has checked the home directory if the file is inside it and otherwise carrying on up to `/`. That is the same walk `sshd`'s `safe_path()` does, which is why an `authorized_keys` file placed outside the home under a world-writable directory such as `/tmp` is rejected outright. Only *write* bits for group/other matter: mode 644 on `authorized_keys` or 755 on `~/.ssh` is accepted by `sshd` and is not flagged.

## authorized_keys — key level

| Finding | Severity | Why | Fix |
| ------- | -------- | --- | --- |
| `RSA N-bit is below 2048` | CRITICAL | Factoring risk | Replace with Ed25519 or RSA 4096 |
| `DSA key` | HIGH | Deprecated; cannot log in on modern `sshd` anyway | Remove |
| `SSH-1 RSA key` | CRITICAL | Protocol 1, long removed | Remove |
| `RSA N-bit is below policy minimum` | MEDIUM | Below `--min-rsa-bits` | Rotate |
| `same key also authorized at: ...` | MEDIUM | One compromised private key opens every listed account; also a sign of shared or copied keys | One key per (person, purpose); remove the extras |
| `same key also listed for this account at: ...` | LOW | The same key twice for one account grants no extra access, but an admin who deletes one entry believes the key is revoked while the other one still admits it | Keep a single entry per key |
| `certificate listed in authorized_keys` | INFO | `sshd` matches a plain key against the line itself and a certificate against a `cert-authority` line holding the CA's plain key; a certificate blob matches neither, so the line is dead weight that looks like an authorisation. It is also left out of the check for keys reused across accounts, because `ssh-keygen -l` reports a certificate under the fingerprint of the key it certifies, which would otherwise make that key look reused | Remove it; to trust the CA, add its plain public key with the `cert-authority` option |
| `uid-0 account key has no from= or command= restriction` | INFO | Unrestricted root key. Common, but a `from=` or `command=` option limits blast radius | Add options where the use case allows |

## Private keys in ~/.ssh

| Finding | Severity | Why | Fix |
| ------- | -------- | --- | --- |
| `world-accessible private key` | CRITICAL | Any local user can copy it | `chmod 600` |
| `group-accessible private key` | HIGH | Group members can copy it | `chmod 600` |
| `owned by X, expected <user> or root` | HIGH | Someone else's key in this account's directory, or a copied home | Investigate |
| `private key has no passphrase` (root) | HIGH | A root-owned key that is one file read away from use elsewhere | Add a passphrase (`ssh-keygen -p`) or move to an agent / hardware key |
| `private key has no passphrase` (other) | MEDIUM | Same, smaller blast radius. Automation keys are often legitimately passphrase-less; pair them with `from=`/`command=` on the receiving side | Same |
| `RSA N-bit ...`, `DSA key` | as above | | Rotate |
| `could not determine whether the key is passphrase-protected` | LOW | Unrecognised file format, an OpenSSH-format key cut short before its closing line, which leaves no way to trust anything read out of it, or a key file holding a byte that is not ASCII (a private-key file is ASCII from end to end, so such a file is corrupt) | Inspect manually |
| `<name>.pub does not match this private key` | LOW | The public file next to the key is stale or belongs to a different key, so anything copied out of it — for example into an `authorized_keys` file — authorises the wrong key | Regenerate it: `ssh-keygen -y -f <key> > <key>.pub` |
| `could not fingerprint private key` | LOW | The key could not be fingerprinted: a passphrase-protected key in the old PEM format with no `.pub` file, a PEM key with no `.pub` that is owned by the account running the tool with any group or other permission bits set (`ssh-keygen` refuses to open such a key), a corrupt or truncated key body in the current OpenSSH format (reported this way even when a `.pub` file is present, since a corrupt file says nothing about which key it was), or a current-format key whose private half `ssh`'s own loader cannot load — mismatched check integers, private fields that do not deserialize, bad padding, or a body mangled in transit (CRLF line endings, indentation). Its algorithm and size were not graded | Fix the permissions if that is the cause; otherwise write the public file (`ssh-keygen -y -f <key> > <key>.pub`) or convert the key to the current format with `ssh-keygen -p -o -f <key>`; for a current-format key `ssh` itself cannot load, regenerate the key and replace it everywhere it is authorised |
