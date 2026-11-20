# Bundled wordlist

`common-passwords.txt` is the **10,000 most common passwords** list from
[SecLists](https://github.com/danielmiessler/SecLists).

- Source URL: <https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt>
- Project: SecLists, by Daniel Miessler and contributors
- License: MIT (see <https://github.com/danielmiessler/SecLists/blob/master/LICENSE>)
- Retrieved: 2026-11-20 (one-time download at build time)

It is committed here so DecryptRE never needs the network at runtime.

## What it is used for

The list is only used to attack **passphrase-protected ciphertext** (Fernet,
AES-CBC, AES-GCM). Trying 10,000 candidate passphrases against a real KDF is
a *dictionary attack*, not a brute-force of the whole keyspace. If the real
passphrase is not in the list, DecryptRE cannot recover it. There is no way
around that for modern cryptography, and the tool does not pretend otherwise.

## Replacing it

You can point DecryptRE at any newline-separated wordlist with
`--wordlist path/to/list.txt`; lines starting with `#` and blank lines are
ignored. Keep the file small enough for the KDF cost to stay reasonable.
