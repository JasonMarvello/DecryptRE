"""Human-readable labels for methods, parameters and confidence.

The CLI and the interactive menu both show results to people who are not
cryptographers, so the wording lives in one place instead of being rebuilt
in each front end.
"""

from typing import Any, Dict, List, Tuple

from .scorer import NON_LATIN_SCORE, SHORT_TEXT_SCORE

DISPLAY_NAMES = {
    "input": "Original input",
    "base64": "Base64",
    "base32": "Base32",
    "base16": "Hex (Base16)",
    "url": "URL encoding",
    "ascii85": "ASCII85",
    "caesar": "Caesar shift",
    "atbash": "Atbash",
    "vigenere": "Vigenere",
    "railfence": "Rail Fence",
    "substitution": "Simple substitution",
    "xor": "XOR",
    "modern": "Modern crypto",
    "openssl": "OpenSSL",
}

ALG_NAMES = {
    "fernet": "Fernet",
    "aes-gcm": "AES-256-GCM",
    "aes-cbc": "AES-256-CBC",
    "des3-cbc": "3DES-CBC (legacy)",
}

# One row per method for `decryptre methods` and the README table.
# ``decrypt`` says how a key-less attempt works; ``key`` says what --key means.
METHODS: List[Dict[str, Any]] = [
    {
        "name": "base64",
        "aliases": ["b64"],
        "encrypt": True,
        "decrypt": "always",
        "auto": True,
        "key": "not used",
        "what": "Reversible encoding, not encryption. Padding is added automatically.",
        "example": 'decryptre decrypt --input "SGVsbG8=" --method base64',
    },
    {
        "name": "base32",
        "aliases": ["b32"],
        "encrypt": True,
        "decrypt": "always",
        "auto": True,
        "key": "not used",
        "what": "Reversible encoding using A-Z and 2-7. Case-insensitive.",
        "example": 'decryptre decrypt --input "JBSWY3DP" --method base32',
    },
    {
        "name": "base16",
        "aliases": ["b16", "hex"],
        "encrypt": True,
        "decrypt": "always",
        "auto": True,
        "key": "not used",
        "what": "Hexadecimal bytes. An optional 0x prefix is accepted.",
        "example": 'decryptre decrypt --input "48656c6c6f" --method hex',
    },
    {
        "name": "url",
        "aliases": ["percent", "urlencode"],
        "encrypt": True,
        "decrypt": "always",
        "auto": True,
        "key": "not used",
        "what": "Percent escapes and + for spaces.",
        "example": 'decryptre decrypt --input "Hello%2C+world" --method url',
    },
    {
        "name": "ascii85",
        "aliases": ["a85"],
        "encrypt": True,
        "decrypt": "always",
        "auto": True,
        "key": "not used",
        "what": "Adobe-style ASCII85. <~ ~> wrappers are accepted.",
        "example": 'decryptre decrypt --input "87cURD]i,\\"Ebo80" --method ascii85',
    },
    {
        "name": "caesar",
        "aliases": ["rot", "rot-n", "rotn", "rot13"],
        "encrypt": True,
        "decrypt": "tries all 26 shifts",
        "auto": True,
        "key": "not used; --shift forces one",
        "what": "Shifts every letter by N places. The best English-looking shift is chosen.",
        "example": 'decryptre decrypt --input "Khoor, Zruog!" --method caesar',
    },
    {
        "name": "atbash",
        "aliases": [],
        "encrypt": True,
        "decrypt": "always (one possible result)",
        "auto": True,
        "key": "not used",
        "what": "Mirrors the alphabet: a<->z, b<->y. Self-inverting.",
        "example": 'decryptre decrypt --input "Svool, Dliow!" --method atbash',
    },
    {
        "name": "vigenere",
        "aliases": ["vig"],
        "encrypt": True,
        "decrypt": "recovers the key (length 1-12)",
        "auto": True,
        "key": "known passphrase/key",
        "what": "Repeating-letter Caesar. Needs a reasonable amount of text.",
        "example": 'decryptre decrypt --input "Rijvs, Uyvjn!" --method vigenere',
    },
    {
        "name": "railfence",
        "aliases": ["rail-fence", "rail"],
        "encrypt": True,
        "decrypt": "tries 2-12 rails",
        "auto": True,
        "key": "not used; --rails forces one",
        "what": "Writes text in a zig-zag and reads it row by row.",
        "example": 'decryptre decrypt --input "Hlo olWrd" --method railfence',
    },
    {
        "name": "substitution",
        "aliases": ["sub"],
        "encrypt": True,
        "decrypt": "best effort (trigram solver)",
        "auto": True,
        "key": "26-letter alphabet",
        "what": "One-to-one letter mapping. Needs a few hundred letters to be reliable.",
        "example": 'decryptre decrypt --input "..." --method substitution --key "qwerty..."',
    },
    {
        "name": "xor",
        "aliases": [],
        "encrypt": True,
        "decrypt": "single byte or repeating key up to 32 bytes",
        "auto": True,
        "key": "known key",
        "what": "Byte-wise XOR. Output is wrapped as decryptre:xor:<base64>.",
        "example": 'decryptre decrypt --input "..." --method xor --key "secret"',
    },
    {
        "name": "fernet",
        "aliases": [],
        "encrypt": True,
        "decrypt": "dictionary attack only",
        "auto": "containers only",
        "key": "passphrase",
        "what": "AES-CBC + HMAC via the Fernet spec, PBKDF2-SHA256 key.",
        "example": 'decryptre decrypt --input "decryptre:v1:..." --method fernet --key "pass"',
    },
    {
        "name": "aes",
        "aliases": ["aes-256", "aes-gcm", "aes-cbc"],
        "encrypt": True,
        "decrypt": "dictionary attack only",
        "auto": "containers only",
        "key": "passphrase",
        "what": "AES-256 in GCM (default) or CBC mode; PBKDF2 or scrypt.",
        "example": 'decryptre decrypt --input "decryptre:v1:..." --method aes --key "pass"',
    },
    {
        "name": "openssl",
        "aliases": ["salted", "openssl-enc"],
        "encrypt": False,
        "decrypt": "passphrase (AES/3DES/DES/Blowfish/CAST5/RC4)",
        "auto": "yes, with key",
        "key": "passphrase",
        "what": "OpenSSL `enc` salted output (Salted__): AES/3DES/DES/Blowfish/CAST5/RC4. Decrypt-only.",
        "example": 'decryptre decrypt --input "U2FsdGVkX1..." --method openssl --key "pass"',
    },
    {
        "name": "des3",
        "aliases": ["3des", "des-ede3"],
        "encrypt": True,
        "decrypt": "dictionary attack only",
        "auto": "containers only",
        "key": "passphrase",
        "what": "3DES-CBC, included for legacy compatibility only. Do not use for new data.",
        "example": 'decryptre decrypt --input "decryptre:v1:..." --method des3 --key "pass"',
    },
]


def display_name(method: str, params: Dict[str, Any] = None) -> str:
    """Human name for a candidate, including the concrete algorithm."""
    if method == "modern":
        alg = (params or {}).get("alg")
        return ALG_NAMES.get(str(alg), f"Modern crypto ({alg})")
    if method == "openssl":
        return str((params or {}).get("alg", "OpenSSL salted"))
    return DISPLAY_NAMES.get(method, method)


def describe_params(method: str, params: Dict[str, Any]) -> str:
    """Plain-language description of the recovered key/parameters."""
    if not params:
        return ""
    parts: List[str] = []
    if method in ("modern", "openssl"):
        if "passphrase" in params:
            parts.append(f'passphrase "{params["passphrase"]}"')
        return ", ".join(parts)
    if "shift" in params:
        parts.append(f"shift {params['shift']}")
    if "rails" in params:
        parts.append(f"{params['rails']} rails")
    if "key" in params:
        key = params["key"]
        if method == "substitution":
            parts.append("recovered 26-letter alphabet")
        elif method == "xor" and params.get("key_length", 1) > 1:
            parts.append(f"repeating key {key} ({params['key_length']} bytes)")
        elif isinstance(key, int):
            parts.append(f"single-byte key 0x{key:02x}")
        else:
            parts.append(f'key "{key}"')
    if params.get("op") == "decode":
        parts.append("one decode layer")
    if params.get("op") == "base64-unwrap":
        parts.append("unwrapped decryptre:xor: token")
    return ", ".join(parts)


def confidence(candidate) -> Tuple[str, str]:
    """Return ``(label, explanation)`` for a candidate's trustworthiness."""
    if candidate.verified:
        if candidate.method == "openssl":
            return (
                "high",
                "the passphrase produced valid padding and readable UTF-8 "
                "(OpenSSL blobs carry no authentication tag).",
            )
        return (
            "high",
            "the passphrase was verified by the cipher itself (authentication tag).",
        )
    text = candidate.text or ""
    has_ascii_letters = any("a" <= ch.lower() <= "z" for ch in text)
    if candidate.score == NON_LATIN_SCORE and not has_ascii_letters:
        return (
            "unscorable",
            "legible text, but outside the English model, so only the format can vouch for it.",
        )
    if candidate.score == SHORT_TEXT_SCORE:
        return ("unknown", "too short to judge whether it is correct.")
    score = candidate.score
    if score >= -8.0:
        return ("high", "reads like ordinary English.")
    if score >= -11.5:
        return ("medium", "mostly English-looking; read it before trusting it.")
    if score >= -15.0:
        return ("low", "weak English signal; probably a wrong guess.")
    return ("very low", "does not read like English; almost certainly a wrong guess.")
