"""Command line interface: ``decryptre decrypt|encrypt|identify``."""

import argparse
import base64
import binascii
import re
import sys
from pathlib import Path
from typing import Iterable, List, Optional

from . import __version__, classical, encodings, modern_crypto, present, xor
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
        )
        if not any(candidate.verified for candidate in results):
            hint = _binary_container_hint(text)
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
            "bundled word list try known passphrases. Nothing uses the network."
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
