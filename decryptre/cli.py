"""Command line interface: ``decryptre decrypt|encrypt|identify``."""

import argparse
import base64
import sys
from pathlib import Path
from typing import Iterable, List, Optional

from . import __version__, classical, encodings, modern_crypto, xor
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
    "aes-cbc": "aes",
    "aes-gcm": "aes",
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
    except OSError:
        # Long tokens and odd names are ciphertext, not paths.
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
    """Make control characters visible without hiding the plaintext."""
    return "".join(
        ch if ch in "\n\t" or 32 <= ord(ch) <= 126 else f"\\x{ord(ch):02x}"
        for ch in text
    )


def print_candidates(candidates: Iterable[Candidate], verbose: bool = False) -> None:
    candidates = list(candidates)
    if not candidates:
        print("No result. Try --method with an explicit cipher, or --max-depth 4.")
        return
    for index, candidate in enumerate(candidates, start=1):
        params = candidate.describe_params()
        header = f"[{index}] score={candidate.score:7.3f}  method={candidate.method}"
        if params:
            header += f"  {params}"
        if verbose and candidate.depth:
            header += f"  depth={candidate.depth}"
        print(header)
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

    if method in ("fernet", "aes"):
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
        plain = modern_crypto.decrypt_modern(text, args.key)
        return [Candidate(plain, "modern", {"alg": method}, score_text(plain))]

    raise SystemExit(f"error: unknown method: {method}")


def cmd_decrypt(args) -> int:
    text = read_input(args.input)
    method = _normalise_method(args.method)

    if method == "auto":
        words = [] if args.no_wordlist else load_wordlist(args.wordlist)
        results = detect(
            text,
            max_depth=args.max_depth,
            max_candidates=args.max_candidates,
            top=args.top,
            wordlist=words,
            include_substitution=not args.no_substitution,
        )
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

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decryptre",
        description=(
            "Offline decryption and encryption of text. "
            "No passphrase mode is a parameter/dictionary search, not a keyspace break."
        ),
        epilog=RESPONSIBLE_USE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"decryptre {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    decrypt = sub.add_parser(
        "decrypt",
        help="decrypt or decode text (auto or a chosen method)",
        description="Decrypt text. With --method auto every supported layer is tried.",
        epilog=RESPONSIBLE_USE,
    )
    decrypt.add_argument("--input", required=True, help="file path, literal text, or - for stdin")
    decrypt.add_argument("--method", default="auto", help="method name or auto (default: auto)")
    decrypt.add_argument("--key", help="passphrase or cipher key")
    decrypt.add_argument("--shift", type=int, help="Caesar shift (default: try all)")
    decrypt.add_argument("--rails", type=int, help="Rail Fence rails (default: try 2-12)")
    decrypt.add_argument("--wordlist", help="offline passphrase list for modern crypto")
    decrypt.add_argument("--no-wordlist", action="store_true", help="do not use the bundled wordlist")
    decrypt.add_argument("--no-substitution", action="store_true", help="skip the slow substitution solver")
    decrypt.add_argument("--max-depth", type=int, default=3, help="maximum peel layers (default: 3)")
    decrypt.add_argument("--max-candidates", type=int, default=2000, help="candidate budget (default: 2000)")
    decrypt.add_argument("--top", type=int, default=5, help="how many results to show (default: 5)")
    decrypt.add_argument("-v", "--verbose", action="count", default=0, help="show extra detail")
    decrypt.set_defaults(func=cmd_decrypt)

    encrypt = sub.add_parser(
        "encrypt",
        help="encrypt or encode text",
        description="Encrypt text with the same methods DecryptRE can decrypt.",
    )
    encrypt.add_argument("--input", required=True, help="file path, literal text, or - for stdin")
    encrypt.add_argument("--method", required=True, help="encoding or cipher name")
    encrypt.add_argument("--key", help="passphrase or cipher key")
    encrypt.add_argument("--shift", type=int, default=3, help="Caesar shift (default: 3)")
    encrypt.add_argument("--rails", type=int, help="Rail Fence rails")
    encrypt.add_argument("--aes-mode", default="gcm", choices=["gcm", "cbc"], help="AES mode (default: gcm)")
    encrypt.add_argument("--kdf", default="pbkdf2", choices=["pbkdf2", "scrypt"], help="key derivation (default: pbkdf2)")
    encrypt.add_argument("--iterations", type=int, default=modern_crypto.DEFAULT_ITERATIONS, help="PBKDF2 iterations")
    encrypt.add_argument("-v", "--verbose", action="count", default=0)
    encrypt.set_defaults(func=cmd_encrypt)

    identify = sub.add_parser(
        "identify",
        help="identify hashes and encodings (hashes cannot be decrypted)",
    )
    identify.add_argument("--input", required=True, help="file path, literal text, or - for stdin")
    identify.add_argument("-v", "--verbose", action="count", default=0)
    identify.set_defaults(func=cmd_identify)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
