# Bundled wordlists

DecryptRE ships two kinds of passphrase data. Both are committed here so the
tool never needs the network at runtime.

## `common-passwords.txt` (fast list)

The **10,000 most common passwords** list from
[SecLists](https://github.com/danielmiessler/SecLists), used by auto mode and
by modern-container scans, where the KDF makes every guess expensive.

- Source URL: <https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt>
- Project: SecLists, by Daniel Miessler and contributors
- License: MIT (see <https://github.com/danielmiessler/SecLists/blob/master/LICENSE>)
- Retrieved: 2026-11-20 (one-time download at build time)

## Multilingual dictionaries

Explicit `--method openssl` scans (and only those by default) combine the
common-password list with the following dictionaries, 1,368,353 unique
candidates in total. Entries are lowercased, de-duplicated, restricted to
3-24 characters, and limited to letters plus `'` and `-`; blank lines and
comments are not stored.

| File | Entries | Source | License |
| --- | --- | --- | --- |
| `dictionary-english.txt` | 269,711 | [word-list](https://github.com/sindresorhus/word-list) (US and UK spellings) | MIT |
| `dictionary-indonesian.txt` | 27,080 | [all-words-in-all-languages](https://github.com/eymenefealtun/all-words-in-all-languages), `Indonesian/Indonesian.txt` | Upstream declares no license |
| `dictionary-hindi.txt` | 391,411 | [all-words-in-all-languages](https://github.com/eymenefealtun/all-words-in-all-languages), `Hindi/Hindi.txt` | Upstream declares no license |
| `dictionary-russian.txt` | 374,091 | [wordlists](https://github.com/kkrypt0nn/wordlists), `wordlists/languages/russian.txt` | Upstream declares no license |
| `dictionary-ukrainian.txt` | 296,059 | [wordlists](https://github.com/kkrypt0nn/wordlists), `wordlists/languages/ukrainian.txt` | Upstream declares no license |

These upstream projects collect factual word lists; the notices above record
where each file came from. Retrieved 2026-11-22.

## What it is used for

The lists are only used to attack **passphrase-protected ciphertext**.
Trying candidates against a real KDF is a *dictionary attack*, not a
brute-force of the whole keyspace. If the real passphrase is not in the list,
DecryptRE cannot recover it. There is no way around that for modern
cryptography, and the tool does not pretend otherwise.

OpenSSL `enc` without `-pbkdf2` uses a cheap key derivation, so the full
dictionary is practical there. Auto mode stays on the 10,000 common passwords
so an ordinary `decryptre decrypt` does not turn into a multi-minute scan.

## Replacing them

You can point DecryptRE at any newline-separated wordlist with
`--wordlist path/to/list.txt`; lines starting with `#` and blank lines are
ignored. Keep the file small enough for the KDF cost to stay reasonable.
