"""Command line interface: ``decryptre decrypt|encrypt|identify``."""

import argparse
import base64
import binascii
import re
import sys
import textwrap
import time
from pathlib import Path
from typing import Iterable, List, Optional

from . import (
    __version__,
    classical,
    encodings,
    incremental,
    modern_crypto,
    openssl_compat,
    present,
    xor,
)
from .auto_detect import XOR_PREFIX, detect
from .containers import ContainerError
from .models import Candidate
from .scorer import score_text

RESPONSIBLE_USE = (
    "Responsible use: decrypt only data you own or have explicit permission "
    "to test. DecryptRE is an educational and CTF tool, not an attack service."
)

METHOD_ALIASES = {
    "rot": "caesar",
    "rot-n": "caesar",
    "rotn": "caesar",
    "rot13": "rot13",
    "rail-fence": "railfence",
    "rail_fence": "railfence",
    "rail": "railfence",
    "vig": "vigenere",
    "sub": "substitution",
    "auto": "auto",
    "all": "auto",
    "base64": "base64",
    "base32": "base32",
    "base16": "base16",
    "hex": "base16",
    "url": "url",
    "ascii85": "ascii85",
    "aes": "aes",
    "aes-256": "aes",
    "aes-cbc": "aes",
    "aes-gcm": "aes",
    "des3": "des3",
    "3des": "des3",
    "des-ede3": "des3",
    "openssl": "openssl",
    "salted": "openssl",
    "salted__": "openssl",
    "openssl-enc": "openssl",
    "fernet": "fernet",
    "xor": "xor",
    "caesar": "caesar",
    "atbash": "atbash",
    "vigenere": "vigenere",
    "railfence": "railfence",
    "substitution": "substitution",
}


def _normalise_method(name: str) -> str:
    key = name.strip().lower()
    return METHOD_ALIASES.get(key, key)


def read_input(value: str) -> str:
    """Read a file when ``value`` names one, otherwise treat it as text."""
    if value == "-":
        return sys.stdin.read()
    try:
        path = Path(value)
        is_file = len(value) < 4096 and path.is_file()
    except (OSError, ValueError):
        # Long tokens, NUL bytes and odd names are ciphertext, not paths.
        is_file = False
    if is_file:
        # surrogateescape keeps arbitrary bytes recoverable for XOR.
        return path.read_text(encoding="utf-8", errors="surrogateescape")
    return value


def load_wordlist(path: Optional[str] = None) -> List[str]:
    """Load a newline-separated passphrase list (bundled by default)."""
    if path is None:
        candidate = Path(__file__).parent / "wordlists" / "common-passwords.txt"
    else:
        candidate = Path(path)
    if not candidate.is_file():
        raise SystemExit(f"error: wordlist not found: {candidate}")
    words = []
    for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(line)
    return words


def _display(text: str) -> str:
    """Make control characters visible without hiding readable Unicode."""
    return "".join(
        ch if ch in "\n\t" or ch.isprintable() else f"\\x{ord(ch):02x}"
        for ch in text
    )


_B64_SHAPE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


class OpenSSLScanStatus:
    """Short progress lines while an OpenSSL wordlist scan runs.

    A 10,000-word scan takes several seconds with no output, which looks like
    a freeze. Print a starting line and a few milestones. Short wordlists
    stay quiet because they finish immediately.
    """

    def __init__(self, stream=None, minimum: int = 500, prefix: str = "") -> None:
        self.stream = stream or sys.stderr
        self.minimum = minimum
        self.prefix = prefix
        self._started = False
        self._last_mark = -1

    def __call__(self, done: int, total: int, digest: str) -> None:
        if total < self.minimum:
            return
        if not self._started:
            print(
                f"{self.prefix}Trying {total:,} passphrases against the "
                f"OpenSSL blob with OpenSSL's legacy key derivation "
                f"(MD5, then SHA-256)...",
                file=self.stream,
                flush=True,
            )
            self._started = True
        if done <= 0:
            self._last_mark = -1
            return
        quarter = max(1, total // 4)
        mark = 4 if done >= total else done // quarter
        if mark > 0 and mark != self._last_mark:
            self._last_mark = mark
            print(
                f"{self.prefix}  {digest}: {done:,}/{total:,} passphrases",
                file=self.stream,
                flush=True,
            )


def _cipher_names() -> str:
    """Human-readable cipher list for hints and errors."""
    labels = list(openssl_compat.available_ciphers())
    aes = [label for label in labels if label.startswith("AES-")]
    others = [label for label in labels if not label.startswith("AES-")]
    parts = (["AES-128/192/256-CBC"] if len(aes) == 3 else aes) + others
    return ", ".join(parts)


def _format_hint(text: str, had_key: bool) -> Optional[str]:
    """Explain a recognizable format that auto mode could not open."""
    if openssl_compat.looks_like(text):
        if had_key:
            message = (
                "This is an OpenSSL 'Salted__' blob, but that passphrase did not "
                "open it. Check the passphrase, or the blob may use a cipher this "
                f"build does not support ({_cipher_names()})."
            )
        else:
            message = (
                "This is an OpenSSL 'Salted__' blob (openssl enc ...). Pass the "
                f"passphrase with --key. Auto mode tries {_cipher_names()} with "
                "OpenSSL's MD5, SHA-256 and PBKDF2 key derivation."
            )
        return textwrap.fill(message, width=78)
    return _binary_container_hint(text)


def _binary_container_hint(text: str) -> Optional[str]:
    """Explain a base64 blob that decodes to an unrecognized binary format."""
    cleaned = "".join(text.split())
    if len(cleaned) < 24 or not _B64_SHAPE.match(cleaned):
        return None
    token = cleaned.replace("-", "+").replace("_", "/")
    token += "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(token, validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(raw) < 16:
        return None
    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    if printable / len(raw) >= 0.6:
        return None
    return (
        "Note: this looks like base64 around an unrecognized binary container.\n"
        "      Auto mode only opens DecryptRE's own decryptre:v1 containers; a\n"
        "      known passphrase cannot be used on an unknown format."
    )


def print_candidates(candidates: Iterable[Candidate], verbose: bool = False) -> None:
    candidates = list(candidates)
    if not candidates:
        print("No result. Try --method with an explicit cipher, or --max-depth 4.")
        return
    confident = any(candidate.verified for candidate in candidates)
    if not confident and candidates[0].score < -8.0:
        print(
            "No verified result. The guesses below are ranked by English-likeness,\n"
            "not proof: treat them as suggestions and read them before trusting them."
        )
        print()
    for index, candidate in enumerate(candidates, start=1):
        name = present.display_name(candidate.method, candidate.params)
        params = present.describe_params(candidate.method, candidate.params)
        label, note = present.confidence(candidate)
        header = f"[{index}] {name}"
        if params:
            header += f"  ·  {params}"
        header += f"  ·  confidence: {label}"
        print(header)
        print(f"    {note}")
        if candidate.chain and candidate.depth:
            print(f"    path: {candidate.chain}")
        if verbose:
            print(
                f"    score={candidate.score:.3f}  depth={candidate.depth}"
                f"  method={candidate.method}"
            )
        for line in _display(candidate.text).splitlines() or [""]:
            print(f"    {line}")
        if index < len(candidates):
            print()


def _xor_wrapper(raw: bytes) -> str:
    token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return XOR_PREFIX + token


def _unwrap_xor(text: str) -> Optional[bytes]:
    stripped = text.strip()
    if not stripped.startswith(XOR_PREFIX):
        return None
    token = stripped[len(XOR_PREFIX):]
    token += "=" * ((-len(token)) % 4)
    try:
        return base64.urlsafe_b64decode(token.encode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# incremental passphrase search (opt-in, OpenSSL only)
# ---------------------------------------------------------------------------


class IncrementalStatus:
    """Throttled progress line for an incremental search."""

    def __init__(self, stream=None, interval: float = 2.0) -> None:
        self.stream = stream or sys.stderr
        self.interval = interval
        self._last = 0.0

    def __call__(self, info) -> None:
        now = time.monotonic()
        if now - self._last < self.interval:
            return
        self._last = now
        print(
            f"  length {info.length}: {info.position:,}/{info.length_total:,} "
            f"({info.passphrases_done:,} tried, {info.rate:,.0f}/s, "
            f"ETA {incremental.format_duration(info.eta_seconds)})",
            file=self.stream,
            flush=True,
        )


def _confirm_incremental(
    estimated_seconds: float, assume_yes: bool = False
) -> None:
    """Ask before a long run; refuse rather than assume "yes" when piped."""
    if assume_yes or estimated_seconds <= incremental.CONFIRM_THRESHOLD_SECONDS:
        return
    minutes = incremental.CONFIRM_THRESHOLD_SECONDS / 60
    if not sys.stdin.isatty():
        raise SystemExit(
            "error: the estimated search time exceeds "
            f"{minutes:.0f} minutes; re-run with --yes to continue "
            "non-interactively"
        )
    print(
        f"Estimated search time exceeds {minutes:.0f} minutes. "
        "Continue? [y/N] ",
        end="",
        file=sys.stderr,
        flush=True,
    )
    answer = sys.stdin.readline().strip().lower()
    if answer not in ("y", "yes"):
        raise SystemExit("cancelled")


def _incremental_decrypt(text: str, args) -> List[Candidate]:
    """Exhaustively try a charset/length space against an OpenSSL blob."""
    try:
        prepared = openssl_compat.prepare_legacy_attempt(text)
    except openssl_compat.OpenSSLError as exc:
        raise SystemExit(f"error: {exc}")
    if prepared.variant_count == 0:
        raise SystemExit(
            "error: no supported block cipher fits this blob; use --key instead"
        )

    allow_risky = args.i_understand_the_risk
    workers = (
        args.workers
        if args.workers is not None
        else openssl_compat.default_workers()
    )
    if args.resume:
        state_path = (
            Path(args.state_file).expanduser()
            if args.state_file
            else incremental.default_state_path(prepared.digest)
        )
        try:
            state = incremental.SearchState.load(state_path)
        except ValueError as exc:
            raise SystemExit(f"error: cannot resume: {exc}")
        if args.charset is not None:
            requested = incremental.resolve_charset(args.charset)
            if requested != state.charset:
                raise SystemExit(
                    "error: --charset does not match the saved checkpoint; "
                    "start a fresh run to change it"
                )
        if args.min_length is not None and args.min_length != state.min_length:
            raise SystemExit(
                "error: --min-length does not match the saved checkpoint"
            )
        if args.max_length is not None and args.max_length != state.max_length:
            raise SystemExit(
                "error: --max-length does not match the saved checkpoint"
            )
        if (
            state.max_length > incremental.MAX_LENGTH_WITHOUT_OVERRIDE
            and not allow_risky
        ):
            raise SystemExit(
                "error: this checkpoint used --max-length above "
                f"{incremental.MAX_LENGTH_WITHOUT_OVERRIDE}; add "
                "--i-understand-the-risk to resume it"
            )
        try:
            incremental.validate_resume(
                state, prepared.digest, prepared.variant_count
            )
        except ValueError as exc:
            raise SystemExit(f"error: {exc}")
        if state.complete:
            raise SystemExit(
                "error: this incremental search is already complete "
                f"({state_path}); delete the checkpoint to start over"
            )
        charset = state.charset
        min_length = state.min_length
        max_length = state.max_length
    else:
        try:
            charset = incremental.resolve_charset(args.charset)
        except ValueError as exc:
            raise SystemExit(f"error: {exc}")
        min_length = (
            incremental.DEFAULT_MIN_LENGTH
            if args.min_length is None
            else args.min_length
        )
        max_length = (
            incremental.DEFAULT_MAX_LENGTH
            if args.max_length is None
            else args.max_length
        )
        try:
            incremental.validate_lengths(min_length, max_length, allow_risky)
        except ValueError as exc:
            raise SystemExit(f"error: {exc}")
        state = incremental.SearchState.create(
            prepared.digest,
            charset,
            min_length,
            max_length,
            prepared.variant_count,
        )
        state_path = (
            Path(args.state_file).expanduser()
            if args.state_file
            else incremental.default_state_path(prepared.digest)
        )

    total_passphrases = incremental.count_passphrases(
        charset, min_length, max_length
    )
    total_trials = total_passphrases * prepared.variant_count
    remaining = incremental.count_remaining(
        charset, min_length, max_length, state.next_length, state.skip
    )
    try:
        measurement = incremental.measure_rate(prepared.try_passphrase)
    except KeyboardInterrupt:
        raise SystemExit(130)
    estimated_seconds = incremental.estimate_seconds(
        remaining, measurement.passphrases_per_second
    )

    print("Incremental passphrase search (exhaustive; opt-in)", file=sys.stderr)
    print(f"  blob: {prepared.digest[:16]}...", file=sys.stderr)
    print(f"  charset: {len(charset)} characters", file=sys.stderr)
    print(f"  lengths: {min_length}..{max_length}", file=sys.stderr)
    print(
        f"  passphrases in full space: {total_passphrases:,}",
        file=sys.stderr,
    )
    print(f"  total cipher/KDF trials: {total_trials:,}", file=sys.stderr)
    print(
        f"  variants per passphrase: {prepared.variant_count} "
        f"(2 KDF digests x {len(prepared.ciphers)} block ciphers)",
        file=sys.stderr,
    )
    print(
        f"  workers: {workers} (pass --workers 1 to disable)",
        file=sys.stderr,
    )
    if args.resume:
        print(
            f"  resuming at: length {state.next_length}, "
            f"position {state.skip:,} ({state.passphrases_done:,} done)",
            file=sys.stderr,
        )
    print(f"  remaining passphrases: {remaining:,}", file=sys.stderr)
    measured_rate = measurement.passphrases_per_second
    rate_text = f"{measured_rate:,.0f}" if measured_rate >= 1 else f"{measured_rate:.3g}"
    print(
        f"  calibration: {rate_text} passphrases/sec "
        f"({measurement.samples} sweeps in {measurement.seconds:.2f}s)",
        file=sys.stderr,
    )
    print(
        "  estimated remaining time: "
        f"{incremental.format_duration(estimated_seconds)}",
        file=sys.stderr,
    )
    print(
        "  Note: exhaustive only inside this charset and length range. It is\n"
        "  exponential and cannot find a passphrase outside those bounds or in\n"
        "  an OpenSSL -pbkdf2 blob. The scan stops at the first readable hit;\n"
        "  'Salted__' has no authentication, so that hit means valid padding\n"
        "  plus readable UTF-8, not cryptographic proof.",
        file=sys.stderr,
    )

    _confirm_incremental(estimated_seconds, assume_yes=args.yes)

    try:
        if workers > 1 and remaining >= incremental.PARALLEL_MIN_PASSPHRASES:
            result = openssl_compat.parallel_incremental_attack(
                text,
                state,
                state_path,
                workers,
                progress=IncrementalStatus(),
            )
        else:
            result = incremental.incremental_attack(
                state,
                prepared.try_passphrase,
                state_path,
                progress=IncrementalStatus(),
            )
    except KeyboardInterrupt:
        print(
            f"\nInterrupted. Progress saved to {state_path}.\n"
            "Re-run the same command with --input plus --resume "
            f"--state-file \"{state_path}\"",
            file=sys.stderr,
        )
        raise SystemExit(130)

    if result is None:
        raise SystemExit(
            "Exhausted every passphrase in the selected charset and length "
            "range. No readable plaintext was found; try a larger charset, "
            "a longer --max-length, or the dictionary/--key."
        )

    passphrase, hit = result
    plain, alg = hit
    print(
        f'Found with passphrase "{passphrase}" at length {len(passphrase)}.',
        file=sys.stderr,
    )
    return [
        Candidate(
            plain,
            "openssl",
            {"alg": alg, "passphrase": passphrase},
            score_text(plain),
            verified=True,
        )
    ]


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------

def _decrypt_with_method(method: str, text: str, args) -> List[Candidate]:
    if method in encodings.ENCODINGS:
        plain = encodings.decode(text, method)
        return [Candidate(plain, method, {}, score_text(plain))]

    if method == "rot13":
        plain = classical.rot13(text)
        return [Candidate(plain, "caesar", {"shift": 13}, score_text(plain))]

    if method == "caesar":
        if args.shift is not None:
            plain = classical.caesar_decrypt(text, args.shift)
            return [Candidate(plain, "caesar", {"shift": args.shift}, score_text(plain))]
        return classical.break_caesar(text, top=args.top)

    if method == "atbash":
        return classical.break_atbash(text)

    if method == "vigenere":
        if not args.key:
            return classical.break_vigenere(text, top=args.top)
        plain = classical.vigenere_decrypt(text, args.key)
        return [Candidate(plain, "vigenere", {"key": args.key}, score_text(plain))]

    if method == "railfence":
        if args.rails is None:
            return classical.break_railfence(text, top=args.top)
        plain = classical.railfence_decrypt(text, args.rails)
        return [Candidate(plain, "railfence", {"rails": args.rails}, score_text(plain))]

    if method == "substitution":
        if args.key:
            plain = classical.substitution_decrypt(text, args.key)
            return [Candidate(plain, "substitution", {"key": args.key}, score_text(plain))]
        return classical.break_substitution(text, top=args.top)

    if method == "xor":
        raw = _unwrap_xor(text)
        if raw is None:
            raw = xor.to_bytes(text)
        if args.key:
            plain = xor.from_bytes(xor.xor_bytes(raw, args.key))
            return [Candidate(plain, "xor", {"key": args.key}, score_text(plain))]
        return xor.break_xor(raw, top=args.top)

    if method == "openssl":
        if args.incremental:
            return _incremental_decrypt(text, args)
        if not args.key:
            words = [] if args.no_wordlist else load_wordlist(args.wordlist)
            if not words:
                raise SystemExit(
                    "error: OpenSSL blobs need --key (no wordlist loaded)"
                )
            workers = (
                args.workers
                if args.workers is not None
                else openssl_compat.default_workers()
            )
            results = openssl_compat.dictionary_attack(
                text,
                words,
                top=args.top,
                progress=OpenSSLScanStatus(),
                workers=workers,
            )
            if not results:
                raise SystemExit(
                    "No passphrase in the wordlist opened this OpenSSL blob. "
                    "Supply --key if you know it."
                )
            return results
        hit = openssl_compat.try_decrypt(text, args.key)
        if hit is None:
            raise SystemExit(
                "error: wrong passphrase, or an OpenSSL cipher this build does "
                f"not support ({_cipher_names()})"
            )
        plain, alg = hit
        return [
            Candidate(
                plain,
                "openssl",
                {"alg": alg, "passphrase": args.key},
                score_text(plain),
                verified=True,
            )
        ]

    if method in ("fernet", "aes", "des3"):
        if not args.key:
            words = [] if args.no_wordlist else load_wordlist(args.wordlist)
            if not words:
                raise SystemExit("error: modern crypto needs --key (no wordlist loaded)")
            results = modern_crypto.dictionary_attack(text, words, top=args.top)
            if not results:
                raise SystemExit(
                    "No passphrase in the wordlist worked. Modern crypto cannot be "
                    "brute-forced; supply --key if you know it."
                )
            return results
        alg = modern_crypto.container_alg(text)
        plain = modern_crypto.decrypt_modern(text, args.key)
        return [
            Candidate(
                plain,
                "modern",
                {"alg": alg or method},
                score_text(plain),
                verified=True,
            )
        ]

    raise SystemExit(f"error: unknown method: {method}")


def cmd_decrypt(args) -> int:
    text = read_input(args.input)
    method = _normalise_method(args.method)

    if args.workers is not None:
        if args.workers < 1:
            raise SystemExit("error: --workers must be at least 1")
        if method != "openssl":
            raise SystemExit(
                "error: --workers only applies to --method openssl"
            )

    if args.incremental:
        if method != "openssl":
            raise SystemExit(
                "error: --incremental requires --method openssl; auto mode "
                "never starts an exhaustive search"
            )
        if args.key:
            raise SystemExit(
                "error: --incremental cannot be combined with --key"
            )
    elif (
        args.charset
        or args.min_length is not None
        or args.max_length is not None
        or args.resume
        or args.state_file
        or args.i_understand_the_risk
        or args.yes
    ):
        raise SystemExit(
            "error: --charset, --min-length, --max-length, --resume, "
            "--state-file, --i-understand-the-risk and --yes require "
            "--incremental"
        )

    if method == "auto":
        # A known passphrase disables the dictionary: the cipher verifies the
        # key, so trying 10,000 wrong ones would only waste time.
        words = (
            []
            if args.key or args.no_wordlist
            else load_wordlist(args.wordlist)
        )
        results = detect(
            text,
            max_depth=args.max_depth,
            max_candidates=args.max_candidates,
            top=args.top,
            wordlist=words,
            include_substitution=not args.no_substitution,
            passphrase=args.key,
            openssl_progress=OpenSSLScanStatus(),
        )
        if not any(candidate.verified for candidate in results):
            hint = _format_hint(text, bool(args.key))
            if hint:
                print(hint)
                print()
    else:
        try:
            results = _decrypt_with_method(method, text, args)
        except (encodings.DecodeError, ContainerError, ValueError) as exc:
            raise SystemExit(f"error: {exc}")

    print_candidates(results, verbose=args.verbose > 0)
    return 0


# ---------------------------------------------------------------------------
# encrypt
# ---------------------------------------------------------------------------

def cmd_encrypt(args) -> int:
    method = _normalise_method(args.method)
    text = read_input(args.input)

    if method in encodings.ENCODINGS:
        print(encodings.encode(text, method))
        return 0
    if method == "rot13":
        print(classical.rot13(text))
        return 0
    if method == "caesar":
        print(classical.caesar_encrypt(text, args.shift if args.shift is not None else 3))
        return 0
    if method == "atbash":
        print(classical.atbash(text))
        return 0
    if method == "vigenere":
        if not args.key:
            raise SystemExit("error: --key is required for Vigenere")
        print(classical.vigenere_encrypt(text, args.key))
        return 0
    if method == "railfence":
        if args.rails is None:
            raise SystemExit("error: --rails is required for Rail Fence")
        print(classical.railfence_encrypt(text, args.rails))
        return 0
    if method == "substitution":
        if not args.key:
            raise SystemExit("error: --key (26-letter alphabet) is required for substitution")
        print(classical.substitution_encrypt(text, args.key))
        return 0
    if method == "xor":
        if not args.key:
            raise SystemExit("error: --key is required for XOR")
        print(_xor_wrapper(xor.xor_encrypt(text, args.key)))
        return 0
    if method == "fernet":
        if not args.key:
            raise SystemExit("error: --key is required for Fernet")
        print(modern_crypto.encrypt_fernet(text, args.key, iterations=args.iterations))
        return 0
    if method == "aes":
        if not args.key:
            raise SystemExit("error: --key is required for AES")
        print(
            modern_crypto.encrypt_aes(
                text,
                args.key,
                mode=args.aes_mode,
                kdf=args.kdf,
                iterations=args.iterations,
            )
        )
        return 0
    if method == "des3":
        if not args.key:
            raise SystemExit("error: --key is required for 3DES")
        print(
            modern_crypto.encrypt_des3(
                text,
                args.key,
                kdf=args.kdf,
                iterations=args.iterations,
            )
        )
        return 0

    raise SystemExit(f"error: unknown method: {method}")


# ---------------------------------------------------------------------------
# identify
# ---------------------------------------------------------------------------

def cmd_identify(args) -> int:
    text = read_input(args.input).strip()
    matches = modern_crypto.identify_hash(text)
    print(f"input length: {len(text)}")
    if matches:
        for match in matches:
            print(f"  {match}")
    else:
        print("  no known encoding or hash shape detected")
    print("  note: hashes are one-way; DecryptRE identifies them but cannot reverse them")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def cmd_methods(args) -> int:
    print("Supported methods")
    print()
    print(f"  {'Name':<14}{'Aliases':<30}{'Encrypt':<9}{'Auto':<16}Key")
    print("  " + "-" * 79)
    for entry in present.METHODS:
        aliases = ", ".join(entry["aliases"]) or "-"
        auto = "yes" if entry["auto"] is True else str(entry["auto"])
        print(
            f"  {entry['name']:<14}{aliases:<30}"
            f"{'yes' if entry['encrypt'] else 'no':<9}{auto:<16}{entry['key']}"
        )
    print()
    print("Details")
    for entry in present.METHODS:
        print()
        print(f"  {entry['name']} — {entry['what']}")
        print(f"    decrypt without a key: {entry['decrypt']}")
        print(f"    --key means: {entry['key']}")
        print(f"    example: {entry['example']}")
    print()
    print(
        "Auto mode peels one layer at a time and ranks results by how much they "
        "look like English.\nAES, Fernet and 3DES cannot be brute-forced: without "
        "the passphrase they are only opened\nby the bundled word list, or not at all."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decryptre",
        description=(
            "Offline decryption and encryption of text.\n"
            "\n"
            "Quick start:\n"
            "  decryptre                          open the interactive menu\n"
            '  decryptre decrypt --input "TEXT"   try every layer, no passphrase needed\n'
            "  decryptre methods                  list methods and what each needs\n"
            "\n"
            "Auto mode tries encodings, then classical ciphers, then XOR, one layer\n"
            "at a time, and ranks everything by how much it looks like English.\n"
            "AES, Fernet and 3DES cannot be brute-forced: supply --key or let the\n"
            "bundled word list try known passphrases. OpenSSL 'Salted__' blobs\n"
            "(openssl enc ...) are opened the same way. Nothing uses the network."
        ),
        epilog=RESPONSIBLE_USE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"decryptre {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    decrypt = sub.add_parser(
        "decrypt",
        help="decrypt or decode text (auto or a chosen method)",
        description=(
            "Decrypt text. --method auto (the default) peels layers: encoding "
            "decodes first, then\nclassical ciphers, then XOR, then modern "
            "containers if a key or word list is available."
        ),
        epilog=RESPONSIBLE_USE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    decrypt.add_argument(
        "--input",
        required=True,
        help="file path, literal text, or - to read stdin",
    )
    decrypt.add_argument(
        "--method",
        default="auto",
        help="auto tries every layer; or name one method (see `decryptre methods`)",
    )
    decrypt.add_argument(
        "--key",
        help=(
            "passphrase or cipher key. In auto mode a passphrase is also tried "
            "against AES/Fernet/3DES containers and is verified by the cipher"
        ),
    )
    decrypt.add_argument(
        "--shift", type=int, help="Caesar shift to use; omit it to try all 26"
    )
    decrypt.add_argument(
        "--rails", type=int, help="Rail Fence rails to use; omit it to try 2-12"
    )
    decrypt.add_argument(
        "--wordlist",
        help="file of passphrases to try, one per line (replaces the bundled list)",
    )
    decrypt.add_argument(
        "--no-wordlist",
        action="store_true",
        help="do not try the bundled 10,000-passphrase list (faster)",
    )
    decrypt.add_argument(
        "--workers",
        type=int,
        default=None,
        help=(
            "worker processes for explicit OpenSSL wordlist/incremental "
            "scans (default: CPU count, capped at 8; 1 disables)"
        ),
    )
    incremental_options = decrypt.add_argument_group(
        "incremental passphrase search (opt-in, OpenSSL only)"
    )
    incremental_options.add_argument(
        "--incremental",
        action="store_true",
        help=(
            "exhaustively try every passphrase over a charset; requires "
            "--method openssl and is never used by auto mode"
        ),
    )
    incremental_options.add_argument(
        "--charset",
        action="append",
        choices=list(incremental.CHARSETS) + ["all"],
        default=None,
        help=(
            "charset component for --incremental; repeat to combine "
            "(default: lower+upper+digits)"
        ),
    )
    incremental_options.add_argument(
        "--min-length",
        type=int,
        default=None,
        help="shortest passphrase length for --incremental (default: 1)",
    )
    incremental_options.add_argument(
        "--max-length",
        type=int,
        default=None,
        help=(
            "longest passphrase length for --incremental (default: 5; "
            "above 6 requires --i-understand-the-risk)"
        ),
    )
    incremental_options.add_argument(
        "--resume",
        action="store_true",
        help="continue an interrupted --incremental search from its checkpoint",
    )
    incremental_options.add_argument(
        "--state-file",
        default=None,
        help=(
            "checkpoint file for --incremental (default: per-blob file in "
            "~/.decryptre/incremental)"
        ),
    )
    incremental_options.add_argument(
        "--i-understand-the-risk",
        action="store_true",
        help=(
            "allow --max-length above 6 (confirmation is still required "
            "unless --yes)"
        ),
    )
    incremental_options.add_argument(
        "--yes",
        action="store_true",
        help=(
            "skip the --incremental time-estimate confirmation; does not "
            "lift the length cap"
        ),
    )
    decrypt.add_argument(
        "--no-substitution",
        action="store_true",
        help="skip the slow substitution solver in auto mode",
    )
    decrypt.add_argument(
        "--max-depth",
        type=int,
        default=3,
        help="how many layers auto may peel (default: 3; more is slower)",
    )
    decrypt.add_argument(
        "--max-candidates",
        type=int,
        default=2000,
        help="work budget per layer (default: 2000); raise it if a stacked cipher is missed",
    )
    decrypt.add_argument(
        "--top", type=int, default=5, help="how many ranked results to print (default: 5)"
    )
    decrypt.add_argument(
        "-v", "--verbose", action="count", default=0, help="add raw scores and depth"
    )
    decrypt.set_defaults(func=cmd_decrypt)

    encrypt = sub.add_parser(
        "encrypt",
        help="encrypt or encode text",
        description="Encrypt text with the same methods DecryptRE can decrypt.",
    )
    encrypt.add_argument(
        "--input", required=True, help="file path, literal text, or - to read stdin"
    )
    encrypt.add_argument(
        "--method", required=True, help="encoding or cipher name (see `decryptre methods`)"
    )
    encrypt.add_argument(
        "--key",
        help="passphrase or cipher key; required for Vigenere, XOR, Fernet, AES and 3DES",
    )
    encrypt.add_argument(
        "--shift", type=int, default=3, help="Caesar shift (default: 3)"
    )
    encrypt.add_argument("--rails", type=int, help="Rail Fence rails")
    encrypt.add_argument(
        "--aes-mode",
        default="gcm",
        choices=["gcm", "cbc"],
        help="AES mode: gcm is authenticated, cbc is the older mode (default: gcm)",
    )
    encrypt.add_argument(
        "--kdf",
        default="pbkdf2",
        choices=["pbkdf2", "scrypt"],
        help="how the passphrase becomes a key (default: pbkdf2)",
    )
    encrypt.add_argument(
        "--iterations",
        type=int,
        default=modern_crypto.DEFAULT_ITERATIONS,
        help="PBKDF2 work factor (default: 200000; higher is slower and stronger)",
    )
    encrypt.add_argument("-v", "--verbose", action="count", default=0)
    encrypt.set_defaults(func=cmd_encrypt)

    methods = sub.add_parser(
        "methods",
        help="list every method, what it needs, and an example",
        description=(
            "List every supported method with its aliases, whether auto mode "
            "tries it, what --key\nmeans for it, and a runnable example."
        ),
    )
    methods.set_defaults(func=cmd_methods)

    identify = sub.add_parser(
        "identify",
        help="identify hashes and encodings (hashes cannot be decrypted)",
    )
    identify.add_argument(
        "--input", required=True, help="file path, literal text, or - to read stdin"
    )
    identify.add_argument("-v", "--verbose", action="count", default=0)
    identify.set_defaults(func=cmd_identify)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        # Bare `decryptre` opens the interactive menu; when input is piped or
        # redirected there is nothing to navigate, so show the help instead.
        if sys.stdin.isatty() and sys.stdout.isatty():
            from .interactive import run

            return run()
        parser.print_help()
        return 0
    args = parser.parse_args(arguments)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
