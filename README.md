# DecryptRE

DecryptRE is a free, open-source Python command-line tool that **decrypts text
with or without a passphrase** and can **encrypt it again** with the same
methods.

It handles encodings (Base64, Base32, hex, URL, ASCII85), classical ciphers
(Caesar/ROT-N, Atbash, Vigenère, Rail Fence, simple substitution), XOR, and
passphrase-based modern crypto (Fernet, AES-256 and legacy 3DES). It also
opens OpenSSL `Salted__` blobs and recognises common hashes.

**Everything runs offline.** There are no API calls, no telemetry, no remote
wordlists, and no internet connection is needed after installation. A test in
the repository enforces this.

---

## ⚠️ Responsible use

DecryptRE is for **education, Capture-The-Flag puzzles, and data you own**.

- Only decrypt messages you created or have explicit permission to test.
- Do not use it against other people's accounts, files, or systems.
- "No passphrase" mode is a puzzle-solving aid, not a way to break real
  encrypted services.

The authors accept no responsibility for misuse. See [LICENSE](LICENSE).

---

## What it can and cannot do

| Situation | What DecryptRE does |
| --- | --- |
| Text is encoded (Base64, hex, ...) | Decodes it. Encodings are not encryption. |
| Text uses a classical cipher | Tries the parameters and ranks results by how much they look like English. |
| Text uses XOR with a short key | Recovers single-byte keys and repeating keys (up to 32 bytes). |
| Text uses Fernet / AES / 3DES **and you know the passphrase** | Decrypts it. |
| Text uses Fernet / AES / 3DES **and you do not know the passphrase** | Tries every passphrase in an offline wordlist (a *dictionary attack*). If the passphrase is not in the list, it cannot be recovered. That is the point of modern cryptography. |
| Text is an OpenSSL `Salted__` blob **and you know the passphrase** | Decrypts it. AES-128/192/256-CBC, 3DES, DES, Blowfish, CAST5 and RC4 are tried with OpenSSL's MD5, SHA-256 or PBKDF2 key derivation. |
| Text is an OpenSSL `Salted__` blob, the passphrase is short, and you opt in | `--incremental` exhaustively tries a chosen charset/length space. It is slow and exponential and never runs automatically. |
| Text is a hash (MD5, SHA-1, SHA-256, SHA-512) | Identifies the likely algorithm and clearly states that hashes are **one-way** and cannot be decrypted. |

Two honest statements that the code and docs repeat:

1. **"No passphrase" is not magic.** For encodings and classical ciphers it is
   a bounded parameter search. For modern crypto it is a dictionary attack.
2. **Modern encryption cannot be brute-forced by this tool.** A real AES or
   Fernet key derived from a strong passphrase is out of reach. The opt-in
   OpenSSL `--incremental` mode is not an exception: it only exhausts short,
   explicitly chosen charsets, and its cost is exponential.

---

## Installation

Requirements: **Python 3.9 or newer**.

The quickest way is from PyPI:

```bash
pip install decryptre
```

Or install from source:

```bash
git clone https://github.com/JasonMarvello/DecryptRE.git
cd DecryptRE
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install .
```

That installs the `decryptre` command. To work on the code instead:

```bash
pip install -e ".[dev]"
```

---

## Quick start

```bash
# Decode Base64
decryptre decrypt --input "SGVsbG8sIHdvcmxkIQ==" --method base64

# Break a Caesar cipher without knowing the shift
decryptre decrypt --input "Wkh txlfn eurzq ira" --method caesar

# Let DecryptRE try every supported layer
decryptre decrypt --input "V2xqcGNwbyBhZmtrd3BkIGxjcCBxZnk6IG9wbnpvcCB4cCwgZXNweSBkc3RxZSB4cCBtbG52Lg=="

# Decrypt something you encrypted with a passphrase
decryptre encrypt --input "Secret note" --method aes --key "correct horse battery staple"
decryptre decrypt --input "decryptre:v1:..." --method aes --key "correct horse battery staple"

# Identify a hash
decryptre identify --input 5d41402abc4b2a76b9719d911017c592

# See every method, what it needs and a runnable example
decryptre methods

# A known passphrase in auto mode: the cipher verifies it
decryptre decrypt --input "decryptre:v1:..." --key "correct horse battery staple"

# OpenSSL `enc` output (starts with U2FsdGVkX1 = "Salted__")
decryptre decrypt --input "U2FsdGVkX1..." --key "passphrase"
```

`--input` accepts a **file path**, a **literal string**, or `-` to read from
standard input.

---

## Interactive mode

Run it with no arguments and you get a menu instead of flags:

```bash
decryptre
```

Arrow keys (or `j`/`k`) move, `1`-`6` jump straight to an option, Enter
selects, `q` goes back and Ctrl+C quits. Choose **Decrypt / decode text**,
paste ciphertext or a file path, optionally give a passphrase, then pick from
the ranked results and ask for another layer if the text is still encoded.
Encrypt and identify work the same way.

`decryptre --help` still prints the full command reference, and when input is
piped (`cat cipher.txt | decryptre`) the help is printed instead of the menu.

---

## Commands

### `decryptre decrypt`

```bash
decryptre decrypt --input <file|text|-> [options]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--method NAME` | `auto` | `auto` peels every layer; or name one method (see `decryptre methods`). |
| `--key TEXT` | none | Passphrase or cipher key. In auto mode a passphrase is also tried against AES/Fernet/3DES containers and verified by the cipher. |
| `--shift N` | try all | Caesar shift. |
| `--rails N` | try 2-12 | Rail Fence rails. |
| `--wordlist PATH` | bundled list | Passphrase list for Fernet/AES/3DES. Replaces the bundled tiers. |
| `--wordlist-tier small\|medium\|large` | `medium` | Bundled list size for explicit `--method openssl`: 10k, 1.37M, or medium plus a locally built RockYou tier. `large` is not shipped on PyPI. |
| `--no-wordlist` | off | Skip the bundled wordlist. |
| `--workers N` | CPU count, capped at 8 | Worker processes for explicit `--method openssl` wordlist and incremental scans. `--workers 1` disables; auto mode stays single-process. |
| `--incremental` | off | Opt-in exhaustive passphrase search for OpenSSL `Salted__` blobs. Requires `--method openssl`; auto mode never starts it. See [Incremental search](#incremental-search-opt-in-exhaustive-passphrase-search). |
| `--charset NAME` | `lower+upper+digits` | Charset component(s) for `--incremental`: `lower`, `upper`, `digits`, `symbols`, `all`. Repeat to combine. |
| `--min-length N` | `1` | Shortest passphrase length for `--incremental`. |
| `--max-length N` | `5` | Longest length for `--incremental`; above `6` requires `--i-understand-the-risk`. |
| `--resume` | off | Continue an interrupted `--incremental` run from its checkpoint. |
| `--state-file PATH` | per-blob file | Checkpoint location for `--incremental`. |
| `--i-understand-the-risk` | off | Allow `--max-length` above `6`. |
| `--yes` | off | Skip the `--incremental` time-estimate confirmation. |
| `--no-substitution` | off | Skip the slow substitution solver in `auto` mode. |
| `--max-depth N` | `3` | Maximum number of layers to peel in `auto` mode. |
| `--max-candidates N` | `2000` | Hard budget for `auto` mode. |
| `--top N` | `5` | How many results to print. |
| `-v`, `--verbose` | off | Show extra detail. |

### `decryptre encrypt`

```bash
decryptre encrypt --input <file|text|-> --method NAME [options]
```

Uses the same method names. `--key` is required for Vigenère, XOR, Fernet and
AES. Extra options: `--shift` (Caesar, default 3), `--rails` (Rail Fence),
`--aes-mode gcm|cbc` (default `gcm`), `--kdf pbkdf2|scrypt` (default
`pbkdf2`), `--iterations` (PBKDF2, default 200000).

### `decryptre methods`

```bash
decryptre methods
```

Lists every supported method with its aliases, whether `auto` tries it,
what `--key` means for it, and a runnable example. Use it instead of
guessing method names.

### `decryptre identify`

```bash
decryptre identify --input <file|text|->
```

Reports whether a value looks like MD5, SHA-1, SHA-256 or SHA-512, and reminds
you that these are one-way functions. It never claims to "decrypt" a hash.

---

## Supported methods

| Method | Aliases | Encrypt | Decrypt without a key | Notes |
| --- | --- | --- | --- | --- |
| Base64 | `b64` | yes | yes | Padding is added automatically. |
| Base32 | `b32` | yes | yes | Case-insensitive. |
| Base16 / hex | `hex`, `b16` | yes | yes | Optional `0x` prefix. |
| URL encoding | `url`, `percent`, `urlencode` | yes | yes | Percent escapes and `+`. |
| ASCII85 | `a85` | yes | yes | Adobe `<~ ~>` wrappers accepted. |
| Caesar / ROT-N | `caesar`, `rot`, `rot-n`, `rot13` | yes | yes (all 26 shifts) | |
| Atbash | `atbash` | yes | yes | Only one possible result. |
| Vigenère | `vig` | yes | yes (key length 1-12) | Needs a decent amount of text. |
| Rail Fence | `railfence`, `rail`, `rail-fence` | yes | yes (2-12 rails) | |
| Simple substitution | `sub` | yes | best effort (trigram solver) | May be partially wrong; read the output. |
| XOR | `xor` | yes | yes (single byte, repeating key up to 32 bytes) | `decryptre:xor:` output is understood automatically. |
| Fernet | `fernet` | yes | dictionary attack only | PBKDF2 + SHA-256. |
| AES-256-GCM / AES-256-CBC | `aes`, `aes-256`, `aes-gcm`, `aes-cbc` | yes | dictionary attack only | 256-bit key; PBKDF2 or scrypt KDF. |
| 3DES-CBC | `des3`, `3des`, `des-ede3` | yes | dictionary attack only | **Legacy/compatibility only: do not use for new encryption.** |
| OpenSSL `Salted__` | `openssl`, `salted`, `openssl-enc` | no | passphrase, dictionary attack or opt-in incremental | Decrypt-only output of `openssl enc ...`; AES/3DES/DES/Blowfish/CAST5/RC4. |

---

## How `--method auto` works

Auto mode peels one layer at a time:

1. Try every applicable encoding decode.
2. Try the classical cipher breakers.
3. Try XOR when the text is binary or just came out of an encoding.
4. Try a supplied passphrase against DecryptRE containers and OpenSSL
   `Salted__` blobs. Fernet and AES-GCM are authenticated, so they are
   reported as `verified`. OpenSSL and CBC padding hits carry no tag, so
   they are reported as `high (unauthenticated)`.
5. Otherwise try the passphrase dictionary on those containers and blobs. A
   short progress line reports the scan so a long one does not look frozen.
   Auto mode never starts `--incremental`; that mode requires an explicit
   `--method openssl --incremental`.
6. Score every result with an offline English model (letter frequencies,
   trigrams and common words), keep the best few as the next frontier, and
   repeat up to `--max-depth`.

A visited set prevents cycles such as Base64 that decodes to itself, and
`--max-candidates` bounds the total work. When several results are plausible,
they are printed best-first so you can choose:

```text
[1] Vigenere  ·  key "lantern"  ·  confidence: high
    reads like ordinary English.
    The password is hidden under the third stone on the beach.

[2] Vigenere  ·  key "nheqqlmwk"  ·  confidence: low
    weak English signal; probably a wrong guess.
    Ran soytlerp it eirune ewyot apl tleog lyfor uc hig aidie.
```

Each result names the method, the recovered key or parameters, the path
that produced it, and a plain-language confidence note. Passphrase results
are always listed first. `verified` means a real authentication tag proved
the key; `high (unauthenticated)` means valid padding plus readable text,
which is a strong guess rather than proof. `--verbose` adds
the raw score and search depth; the score is a ranking aid, not a
probability.

---

## The `decryptre:v1:` container

AES needs a salt, an IV/nonce and the KDF settings. Instead of asking you to
remember them, `encrypt` stores them beside the ciphertext in a small,
self-describing envelope:

```text
decryptre:v1:<urlsafe-base64 of a JSON object>
```

```json
{
  "v": 1,
  "alg": "aes-gcm",
  "kdf": "pbkdf2",
  "iterations": 200000,
  "salt": "...",
  "nonce": "...",
  "tag": "...",
  "ciphertext": "..."
}
```

Fernet containers store the Fernet token plus the salt and iteration count.
3DES containers use the same envelope with `"alg": "des3-cbc"` and an
8-byte IV. AES-GCM authenticates the whole envelope; AES-CBC and 3DES-CBC
are validated by padding.
A wrong passphrase raises a clear error instead of printing garbage.

XOR encryption prints `decryptre:xor:<base64>` for the same reason: it keeps
the ciphertext safe to copy through a terminal or a text file.

---

## Examples

The [`examples/`](examples/) folder contains ready-to-run ciphertexts and the
exact commands and output in [`examples/expected-output.md`](examples/expected-output.md).

```bash
decryptre decrypt --input examples/caesar.txt --method caesar
decryptre decrypt --input examples/vigenere.txt --method vigenere
decryptre decrypt --input examples/layered.txt
decryptre decrypt --input examples/fernet.txt --method fernet --key sunshine
```

---

## Wordlists

Bundled wordlists are split into tiers. The files are streamed line by line as
raw bytes, so a scan does not load a multi-million-line list into memory or
duplicate it across worker processes. Counts and file order come from
[`decryptre/wordlists/manifest.json`](decryptre/wordlists/manifest.json); the
medium tier is globally deduplicated at build time.

| Tier | Candidates | Used by | Shipped on PyPI |
| --- | ---: | --- | --- |
| `small` | 10,001 | Auto mode and modern-container scans; optional for explicit OpenSSL | yes |
| `medium` | 1,368,353 | Default for explicit `--method openssl` | yes |
| `large` | medium + local RockYou | Optional local build for explicit `--method openssl` | **no** |

Provenance and licenses for the shipped lists are in
[`decryptre/wordlists/SOURCE.md`](decryptre/wordlists/SOURCE.md).

```bash
# Fast 10k scan, or the default 1.37M multilingual scan.
decryptre decrypt --input blob.txt --method openssl --wordlist-tier small
decryptre decrypt --input blob.txt --method openssl

# Replace the tiers with your own list.
decryptre decrypt --input blob.txt --method openssl --wordlist my-words.txt
```

`--wordlist` replaces the bundled tiers; `--wordlist-tier` cannot be combined
with it, with `--key`, `--incremental`, or `--no-wordlist`. Auto mode stays on
`small` and rejects the tier option, so an ordinary decode never turns into a
multi-minute scan.

### Optional local `large` tier (RockYou)

RockYou is a 2009 breach corpus of about 14.3 million real passwords. It has
**no explicit license** and contains other people's data, so DecryptRE does
**not** ship it and `pip install decryptre` never downloads it. The `large`
tier is an explicitly opt-in, local-only build for authorized testing.

From a source checkout:

```bash
python tools/build_wordlists.py --fetch-rockyou
```

The script prints a provenance and ethics notice first and requires you to
type `I understand` before it downloads anything (`--yes` skips the prompt in
automation). It removes entries already in the medium tier and duplicates
inside RockYou, then writes `decryptre/wordlists/rockyou-large.txt.gz` plus a
local metadata file with the count and SHA-256. Both are ignored by Git and
excluded from the package; delete them with
`python tools/build_wordlists.py --remove-rockyou`. Without that local build,
`--wordlist-tier large` prints the build command instead of failing obscurely.

`python tools/build_wordlists.py --verify` checks the shipped tiers for
duplicates; add `--write-manifest` to refresh the committed counts.

The substitution solver uses aggregate English trigram statistics derived
from a public-domain book; see
[`decryptre/data/SOURCE.md`](decryptre/data/SOURCE.md). Only counts are
included, never any text from the source.

---

## Parallel scans (explicit OpenSSL only)

When `--method openssl` runs a wordlist scan or `--incremental`, DecryptRE
uses one worker process per available CPU (capped at 8) by default.
`--workers 1` restores the single-process path, and any positive number
overrides the default.

Work is split into ordered 500-candidate chunks. Dictionary chunks are read
from the tier stream on demand, with only a few chunks in flight at once, so
the parent process does not build a futures list for all 1.37M (or 15M local)
candidates. Results are still consumed in the original order, so a dictionary
hit or incremental hit is the same first readable result the serial scan
would have found. Later chunks stop as soon as an earlier chunk reports a
hit. Incremental checkpoints advance only over the contiguous completed
prefix, so a resume never skips work that is still in flight.

Auto mode and the modern AES/Fernet/3DES dictionary do not use this pool;
`--workers` is rejected outside explicit OpenSSL scans.

### Measured wordlist cost

Measured on 2026-11-22 on a 2-core Linux cloud runner against an OpenSSL
AES-256-CBC blob whose passphrase is absent from the list, so both KDF phases
run to exhaustion. Times include process startup and streaming.

| Tier | Candidates | 1 worker | 2 workers |
| --- | ---: | ---: | ---: |
| `small` | 10,001 | 3.45 s | 2.14 s |
| `medium` | 1,368,353 | 7 m 37 s | 4 m 03 s |
| `large` | 15,645,659 (medium + 14,277,306 local) | not full-scanned here | not full-scanned here |

Peak resident memory was 31.5 MB for the serial medium scan and 35.6 MB for
the two-worker scan, so the list is streamed rather than copied into every
worker. Streaming all 15,645,659 large-tier candidates once, without scanning,
took 7.2 s and 14.6 MB RSS. A large scan is a deliberate offline job: at the
measured medium rate (5,688 candidates/s with two workers) it is roughly
46 minutes on two cores, or around 92 minutes on one. That full 15M scan was
not run on this 2-core runner; a 1M RockYou slice took 2 m 56 s (5,688
candidates/s, 31.8 MB peak RSS), which is the basis for the projection.

## Incremental search (opt-in, exhaustive passphrase search)

The dictionary remains the default. `--incremental` is a separate, opt-in
mode for **OpenSSL `Salted__` blobs only**. It is never started by
`--method auto`, and it does not change the wordlist path.

It is a mask-style exhaustive search over a global charset: every
one-character candidate, then every two-character candidate, and so on.
Within those bounds candidates are tried in a fixed order, with no
randomness, no mutation and no duplicates. "Exhaustive" means exhaustive
inside the selected charset and length range, not that it can find any
passphrase.

```bash
# Try every 1-4 character lowercase/digit passphrase.
decryptre decrypt --input blob.txt --method openssl --incremental \
  --charset lower --charset digits --min-length 1 --max-length 4

# Resume an interrupted run. The charset and lengths come from the state file.
decryptre decrypt --input blob.txt --method openssl --incremental --resume

# Non-interactive use: --yes skips the time-estimate prompt only.
decryptre decrypt --input blob.txt --method openssl --incremental \
  --charset digits --max-length 3 --yes
```

Before starting, the CLI measures the actual rate on this machine with a few
hundred dummy passphrases, then prints the passphrase count, the cipher/KDF
variant count, the total number of decryption trials and an estimated time.
If the estimate is over 10 minutes it asks `y/N`; when stdin is not a
terminal it refuses unless `--yes` is given. `--max-length` defaults to 5;
values above 6 need `--i-understand-the-risk`.

The search covers OpenSSL's legacy `EVP_BytesToKey` derivation (MD5 then
SHA-256) across AES-128/192/256-CBC, 3DES-CBC, DES-CBC, Blowfish-CBC and
CAST5-CBC. RC4 is excluded, as in the dictionary path. `-pbkdf2` blobs
still require `--key`, because 10,000 KDF iterations per guess would make
the estimate meaningless.

### Cost is exponential

Counts are cumulative passphrases up to that length. Times are illustrative
at 2,500 passphrases/sec (roughly the rate measured on the development
machine; each passphrase tries up to 14 variants), but the CLI prints the
measured rate for your machine.

| Max length | 62-char passphrases | time at 2,500/s | 95-char passphrases | time at 2,500/s |
| --- | --- | --- | --- | --- |
| 1 | 62 | 0.02 s | 95 | 0.04 s |
| 2 | 3,906 | 1.6 s | 9,120 | 3.6 s |
| 3 | 242,234 | 1.6 min | 866,495 | 5.8 min |
| 4 | 15,018,570 | 1.7 h | 82,317,120 | 9.1 h |
| 5 | 931,151,062 | 4.3 days | 7,820,126,495 | 36 days |
| 6 | 57,731,366,166 | 267 days | 742,912,017,120 | 9.4 years |

Length 5-6 is already impractical on most machines, and a 7+ character
passphrase is not something to attack this way. Digits-only spaces are much
smaller (1,111,110 candidates through length 6, about 7.4 minutes at
2,500/s), but they only help if the passphrase really uses digits only.
Use the dictionary and targeted guesses first; this is the last resort.

### Checkpoints and resume

Progress is checkpointed every five seconds or 4,096 passphrases, and at
each length boundary. With multiple workers, only completed chunks in the
contiguous prefix advance the checkpoint. Ctrl+C also saves the current
position. The state
file lives at `~/.decryptre/incremental/<blob>.json` by default and can be
changed with `--state-file`. It stores only positions and settings, never a
passphrase or plaintext. `--resume` continues at the exact length and
position; the blob and cipher-variant set must match. To change the charset
or lengths, start a fresh run (or delete the state file).

### What a hit proves

`Salted__` has no authentication tag. A hit means the key produced valid
padding plus readable UTF-8 (and a reasonable English score), not
cryptographic proof. The scan stops at the first readable hit, so a rare
false positive can end it before the real passphrase is reached. It is much
stronger than a random guess, but always read the output before trusting
it. This mode cannot find a passphrase outside the selected charset, longer
than `--max-length`, or one used with OpenSSL `-pbkdf2`.

---

## Limitations

- **Modern crypto is not brute-forced.** Fernet/AES/3DES are only opened when
  the passphrase is supplied or present in the wordlist. OpenSSL `Salted__`
  gets the opt-in exhaustive mode described above; auto never uses it.
- **Incremental search is exponential and opt-in.** `--incremental` only
  exhausts a chosen OpenSSL charset/length space. It cannot reach a strong or
  long passphrase, and it never runs in auto mode.
- **3DES is legacy.** Its 64-bit block and 112-bit effective key are
  obsolete. It is included only to read old data; use AES-256 for anything
  new.
- **OpenSSL support is limited to `Salted__` blobs.** Output from
  `openssl enc ... -salt` is understood; `-nosalt`, raw `-K`/`-iv` keys and
  ciphers outside AES/3DES/DES/Blowfish/CAST5/RC4 are not.
- **Short text is hard.** Vigenère and substitution need a reasonable amount
  of text; a five-word message may not be enough.
- **Substitution solving is best effort.** It usually solves a paragraph, but
  always read the result before trusting it.
- **Hashes cannot be reversed.** `identify` only names the algorithm.
- **One layer at a time.** Auto mode follows a beam of promising results, not
  every possible path. Increase `--max-depth`, `--max-candidates` or `--top`
  if a deep puzzle is missed.
- **This is not a password cracker for online services.** It never connects to
  anything.

---

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest
```

The test suite covers every module, includes known cipher vectors, checks
layered detection, and asserts that the package imports no networking code.

Project layout:

```text
decryptre/
  encodings.py      Base64/Base32/Base16/URL/ASCII85
  classical.py      Caesar, Atbash, Vigenere, Rail Fence, substitution
  xor.py            XOR encryption and key recovery
  modern_crypto.py  Fernet, AES, dictionary attack, hash identification
  containers.py     the decryptre:v1 envelope
  ngrams.py         offline English trigram model
  scorer.py         English-likelihood scoring
  present.py        method names, parameters and confidence wording
  openssl_compat.py OpenSSL `Salted__` decryption
  incremental.py    opt-in exhaustive passphrase search
  auto_detect.py    layered search
  cli.py            the command line
  data/             trigram counts (+ source notes)
  wordlists/        bundled passphrase list (+ source notes)
tests/              pytest suite
examples/           sample ciphertexts and expected output
```

---

## Contributing

Contributions are welcome, especially beginner-friendly ones.

1. Open an issue describing the bug or the method you want to add.
2. Fork the repository and create a branch.
3. Add tests for your change and run `python -m pytest`.
4. Keep the code readable: this project is maintained by someone learning.
5. Open a pull request with a short explanation.

Please keep DecryptRE offline and keep the "does not break modern encryption"
statements accurate.

---

## Credits

- [SecLists](https://github.com/danielmiessler/SecLists) for the common
  password list (MIT).
- Project Gutenberg for the public-domain text used to derive trigram counts.
- The Python `cryptography` and `pycryptodome` projects for the crypto
  primitives.

## License

[MIT](LICENSE) © 2026 Jason Marvello
