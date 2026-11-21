"""OpenSSL ``enc`` compatibility (the ``Salted__`` format).

``openssl enc -aes-256-cbc -a -salt -pass pass:...`` writes::

    base64("Salted__" + 8-byte salt + ciphertext)

The key and IV come from OpenSSL's ``EVP_BytesToKey`` (MD5 by default, or the
digest chosen with ``-md``), or from PBKDF2 when ``-pbkdf2`` was used. Newer
OpenSSL versions still emit this format, so it is common in files and pasted
messages.

Only decryption is provided: DecryptRE does not reimplement ``openssl enc``
output. Verification is padding + valid UTF-8 + printable text, because the
format carries no authentication tag.
"""

import base64
import hashlib
from typing import Iterable, List, Optional, Tuple

from Crypto.Cipher import AES, ARC4, DES, DES3
from Crypto.Util.Padding import unpad

from .models import Candidate
from .scorer import printable_ratio, score_text

MAGIC = b"Salted__"
SALT_SIZE = 8
PBKDF2_ITERATIONS = 10_000


class OpenSSLError(ValueError):
    """Raised when a value is not a supported OpenSSL salted blob."""


# Each entry: (label, module, key length, IV length)
_CIPHERS = (
    ("AES-256-CBC", AES, 32, 16),
    ("AES-192-CBC", AES, 24, 16),
    ("AES-128-CBC", AES, 16, 16),
    ("3DES-CBC", DES3, 24, 8),
    ("DES-CBC", DES, 8, 8),
    ("RC4", ARC4, 16, 0),
)


def _decode_payload(text: str) -> Optional[bytes]:
    """Return the raw ``Salted__`` bytes, accepting base64 or raw text."""
    stripped = text.strip()
    if not stripped:
        return None
    token = "".join(stripped.split()).replace("-", "+").replace("_", "/")
    token += "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(token, validate=True)
    except (ValueError, base64.binascii.Error):
        raw = None
    if raw and raw.startswith(MAGIC):
        return raw
    try:
        raw_text = stripped.encode("latin-1")
    except UnicodeEncodeError:
        return None
    if raw_text.startswith(MAGIC):
        return raw_text
    return None


def looks_like(text: str) -> bool:
    """True when ``text`` is an OpenSSL ``Salted__`` blob (base64 or raw)."""
    raw = _decode_payload(text)
    return bool(raw and len(raw) > 16)


def _split(text: str) -> Tuple[bytes, bytes]:
    raw = _decode_payload(text)
    if not raw:
        raise OpenSSLError("not an OpenSSL 'Salted__' blob")
    salt = raw[len(MAGIC):len(MAGIC) + SALT_SIZE]
    body = raw[len(MAGIC) + SALT_SIZE:]
    if len(salt) != SALT_SIZE or not body:
        raise OpenSSLError("truncated OpenSSL salted blob")
    return salt, body


def evp_bytes_to_key(
    passphrase: bytes,
    salt: bytes,
    key_length: int,
    iv_length: int,
    digest: str = "md5",
) -> Tuple[bytes, bytes]:
    """OpenSSL's EVP_BytesToKey (the KDF used without ``-pbkdf2``)."""
    material = b""
    previous = b""
    while len(material) < key_length + iv_length:
        previous = hashlib.new(digest, previous + passphrase + salt).digest()
        material += previous
    return material[:key_length], material[key_length:key_length + iv_length]


def _pbkdf2_key(
    passphrase: bytes, salt: bytes, key_length: int, iv_length: int
) -> Tuple[bytes, bytes]:
    material = hashlib.pbkdf2_hmac(
        "sha256", passphrase, salt, PBKDF2_ITERATIONS, key_length + iv_length
    )
    return material[:key_length], material[key_length:]


def _plaintext(data: bytes) -> Optional[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    if any(ord(ch) < 32 and ch not in "\r\n\t" for ch in text):
        return None
    # A wrong key can stumble through padding. Short gibberish often contains
    # a few non-ASCII characters, so short plaintext must be plain ASCII;
    # longer text needs to be almost entirely printable.
    if len(text) < 20 and not text.isascii():
        return None
    if printable_ratio(text) < 0.98:
        return None
    return text


def _decrypt_with(
    body: bytes, key: bytes, iv: bytes, label: str, module
) -> Optional[Tuple[str, str]]:
    try:
        if module is ARC4:
            data = ARC4.new(key).decrypt(body)
        else:
            data = unpad(module.new(key, module.MODE_CBC, iv).decrypt(body), module.block_size)
    except ValueError:
        return None
    plain = _plaintext(data)
    return (plain, label) if plain is not None else None


def try_decrypt(token_text: str, passphrase: str) -> Optional[Tuple[str, str]]:
    """Decrypt an OpenSSL salted blob with a known passphrase.

    Returns ``(plaintext, algorithm_label)`` or ``None``. Tries the legacy
    MD5/SHA-256 key derivation first, then OpenSSL's ``-pbkdf2`` variant.
    """
    try:
        salt, body = _split(token_text)
    except OpenSSLError:
        return None
    password = passphrase.encode("utf-8")

    for digest in ("md5", "sha256"):
        for label, module, key_length, iv_length in _CIPHERS:
            if module is not ARC4 and len(body) % module.block_size:
                continue
            key, iv = evp_bytes_to_key(
                password, salt, key_length, iv_length, digest
            )
            hit = _decrypt_with(body, key, iv, f"OpenSSL {label} ({digest.upper()})", module)
            if hit:
                return hit

    for label, module, key_length, iv_length in _CIPHERS:
        if module is not ARC4 and len(body) % module.block_size:
            continue
        key, iv = _pbkdf2_key(password, salt, key_length, iv_length)
        hit = _decrypt_with(
            body, key, iv, f"OpenSSL {label} (PBKDF2-SHA256)", module
        )
        if hit:
            return hit
    return None


def dictionary_attack(
    token_text: str, wordlist: Iterable[str], top: int = 2
) -> List[Candidate]:
    """Try a wordlist against an OpenSSL salted blob.

    The legacy KDF is cheap (no iteration count), so a bundled wordlist is
    practical here. The PBKDF2 variant is not wordlisted: at 10,000 iterations
    per guess it would turn seconds into minutes, so `--key` is required for
    those blobs.
    """
    try:
        salt, body = _split(token_text)
    except OpenSSLError:
        return []

    found: List[Candidate] = []
    seen = set()
    passwords = []
    for word in wordlist:
        word = word.strip()
        if word and word not in seen:
            seen.add(word)
            passwords.append(word.encode("utf-8"))

    # Fast path: EVP_BytesToKey with MD5 and SHA-256. RC4 is excluded: it is
    # a stream cipher with no padding or tag, so a wrong key produces
    # printable-looking output often enough to make wordlist hits meaningless.
    # It remains available with an explicit --key.
    for digest in ("md5", "sha256"):
        for password in passwords:
            for label, module, key_length, iv_length in _CIPHERS:
                if module is ARC4:
                    continue
                if len(body) % module.block_size:
                    continue
                key, iv = evp_bytes_to_key(
                    password, salt, key_length, iv_length, digest
                )
                hit = _decrypt_with(
                    body,
                    key,
                    iv,
                    f"OpenSSL {label} ({digest.upper()})",
                    module,
                )
                if hit:
                    plain, alg = hit
                    found.append(
                        Candidate(
                            plain,
                            "openssl",
                            {"alg": alg, "passphrase": password.decode("utf-8", "replace")},
                            score_text(plain),
                            verified=True,
                        )
                    )
                    break
            if found:
                return found[:top]

    return found
