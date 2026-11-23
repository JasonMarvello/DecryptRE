# Bundled and local wordlists

DecryptRE uses two shipped tiers (`small` and `medium`) and one optional,
local-only tier (`large`). The shipped files are committed so the tool never
needs the network at runtime. `decryptre/wordlists/manifest.json` records the
ordered files and candidate counts; `python tools/build_wordlists.py --verify`
checks them and can refresh the manifest.

## Tiers

| Tier | Candidates | Contents | Shipped on PyPI |
| --- | ---: | --- | --- |
| `small` | 10,001 | The SecLists common-password list as retrieved | yes |
| `medium` | 1,368,353 | `small` + English (US/UK), Indonesian, Hindi, Russian, Ukrainian dictionaries | yes |
| `large` | medium + local RockYou | The medium tier plus a deduplicated RockYou build | **no** |

The medium files are globally deduplicated at build time: no candidate appears
in more than one of the six files. The loader yields raw bytes, so lists with
arbitrary byte sequences are not lossy. Counts are verified by
`tests/test_wordlists.py` and the builder.

## `common-passwords.txt` (small)

The **10,000 most common passwords** list from
[SecLists](https://github.com/danielmiessler/SecLists), used by auto mode and
by modern-container scans, where the KDF makes every guess expensive.

- Source URL: <https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt>
- Project: SecLists, by Daniel Miessler and contributors
- License: MIT (see <https://github.com/danielmiessler/SecLists/blob/master/LICENSE>)
- Retrieved: 2026-11-20 (one-time download at build time)

The file contains 10,001 non-empty entries as retrieved; blank lines and
comments are not counted or yielded by the streaming loader.

## Multilingual dictionaries (medium)

Explicit `--method openssl` scans use the medium tier by default. Entries are
lowercased, de-duplicated, restricted to 3-24 characters, and limited to
letters plus `'` and `-`; blank lines and comments are not stored.

| File | Entries | Source | License |
| --- | --- | --- | --- |
| `dictionary-english.txt` | 269,711 | [word-list](https://github.com/sindresorhus/word-list) (US and UK spellings) | MIT |
| `dictionary-indonesian.txt` | 27,080 | [all-words-in-all-languages](https://github.com/eymenefealtun/all-words-in-all-languages), `Indonesian/Indonesian.txt` | Upstream declares no license |
| `dictionary-hindi.txt` | 391,411 | [all-words-in-all-languages](https://github.com/eymenefealtun/all-words-in-all-languages), `Hindi/Hindi.txt` | Upstream declares no license |
| `dictionary-russian.txt` | 374,091 | [wordlists](https://github.com/kkrypt0nn/wordlists), `wordlists/languages/russian.txt` | Upstream declares no license |
| `dictionary-ukrainian.txt` | 296,059 | [wordlists](https://github.com/kkrypt0nn/wordlists), `wordlists/languages/ukrainian.txt` | Upstream declares no license |

These upstream projects collect factual word lists; the notices above record
where each file came from. Retrieved 2026-11-22. The total includes the 10,001
small-tier entries: 10,001 + 269,711 + 27,080 + 391,411 + 374,091 + 296,059 =
1,368,353 unique candidates.

## Optional local `large` tier (RockYou)

RockYou is a password corpus from a 2009 breach of the RockYou service. It has
about 14.3 million lines and **no explicit license**; security projects such as
SecLists, Kali Linux and Weakpass redistribute it for defensive testing and
research. It contains real people's passwords and other personal strings.

Because of that, the large tier is not committed, not packaged, and never
downloaded automatically. A user with a source checkout can opt in:

```bash
python tools/build_wordlists.py --fetch-rockyou
```

The script:

1. Prints a provenance and ethics notice and requires the phrase
   `I understand` before downloading (or `--yes` in automation).
2. Downloads RockYou from SecLists, with the Weakpass mirror as a fallback.
3. Streams the corpus through a temporary SQLite index, removing candidates
   already present in `medium` and duplicates inside RockYou.
4. Writes `rockyou-large.txt.gz` and `rockyou-large.json` under this directory,
   with the unique count, source, retrieval date and SHA-256.
5. Leaves the files untracked and outside the wheel/sdist.

Use `--source path/to/rockyou.txt` to build from an existing local copy,
`--force` to rebuild, and `--remove-rockyou` to delete the local files.
`--wordlist-tier large` then streams `medium` followed by the local RockYou
file. Do not redistribute the artifact; use it only on data you own or have
explicit permission to test.

## What it is used for

The lists are only used to attack **passphrase-protected ciphertext**.
Trying candidates against a real KDF is a *dictionary attack*, not a
brute-force of the whole keyspace. If the real passphrase is not in the list,
DecryptRE cannot recover it. There is no way around that for modern
cryptography, and the tool does not pretend otherwise.

OpenSSL `enc` without `-pbkdf2` uses a cheap key derivation, so the full
medium tier is practical there. Auto mode stays on the 10,000 common passwords
so an ordinary `decryptre decrypt` does not turn into a multi-minute scan.
RockYou is optional because its size and provenance are both significant; the
default install never includes it.

## Replacing them

You can point DecryptRE at any newline-separated wordlist with
`--wordlist path/to/list.txt`; lines starting with `#` and blank lines are
ignored. Custom lists are streamed and are not de-duplicated, so keep them
small enough for the KDF cost to stay reasonable.
