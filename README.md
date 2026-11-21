# DecryptRE

DecryptRE is a free, open-source Python command-line tool that **decrypts text
with or without a passphrase** and can **encrypt it again** with the same
methods.

It handles encodings (Base64, Base32, hex, URL, ASCII85), classical ciphers
(Caesar/ROT-N, Atbash, Vigenère, Rail Fence, simple substitution), XOR, and
passphrase-based modern crypto (Fernet, AES-256 and legacy 3DES). It also
recognises common hashes.

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
| Text is a hash (MD5, SHA-1, SHA-256, SHA-512) | Identifies the likely algorithm and clearly states that hashes are **one-way** and cannot be decrypted. |

Two honest statements that the code and docs repeat:

1. **"No passphrase" is not magic.** For encodings and classical ciphers it is
   a bounded parameter search. For modern crypto it is a dictionary attack.
2. **Modern encryption cannot be brute-forced by this tool.** A real AES or
   Fernet key derived from a strong passphrase is out of reach.

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
| `--wordlist PATH` | bundled list | Passphrase list for Fernet/AES/3DES. |
| `--no-wordlist` | off | Skip the bundled wordlist. |
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

---

## How `--method auto` works

Auto mode peels one layer at a time:

1. Try every applicable encoding decode.
2. Try the classical cipher breakers.
3. Try XOR when the text is binary or just came out of an encoding.
4. Try a supplied passphrase against DecryptRE containers; the cipher
   verifies it, so the result is marked high confidence.
5. Otherwise try the passphrase dictionary on DecryptRE containers.
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
verified by the cipher are always listed first and say so. `--verbose` adds
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

The bundled `decryptre/wordlists/common-passwords.txt` is the 10,000 most
common passwords list from [SecLists](https://github.com/danielmiessler/SecLists)
(MIT). Provenance and license are documented in
[`decryptre/wordlists/SOURCE.md`](decryptre/wordlists/SOURCE.md).

Use your own list with `--wordlist path/to/list.txt` (one candidate per line;
blank lines and `#` comments are ignored), or skip the bundled one with
`--no-wordlist`. A longer list means more KDF work, so it is slower.

The substitution solver uses aggregate English trigram statistics derived
from a public-domain book; see
[`decryptre/data/SOURCE.md`](decryptre/data/SOURCE.md). Only counts are
included, never any text from the source.

---

## Limitations

- **Modern crypto is not brute-forced.** Fernet/AES/3DES are only opened when
  the passphrase is supplied or present in the wordlist.
- **3DES is legacy.** Its 64-bit block and 112-bit effective key are
  obsolete. It is included only to read old data; use AES-256 for anything
  new.
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
