"""Modern, passphrase-based cryptography: Fernet and AES (CBC / GCM).

Unlike the classical ciphers, these cannot be broken by guessing a few
parameters. Without a passphrase DecryptRE runs a *dictionary attack*: it
tries each word in an offline list as the passphrase. If the real passphrase
is not in that list, decryption is not possible -- that is the point of
modern cryptography, and this module does not pretend otherwise.

Hashes (MD5/SHA-*) are one-way and are only *identified*, never "decrypted".
"""

import base64
import hashlib
import os
from typing import Iterable, List, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad

from .containers import ContainerError, is_container, pack, unpack
from .models import Candidate
from .scorer import score_text

DEFAULT_ITERATIONS = 200_000
SALT_SIZE = 16
IV_SIZE = 16
NONCE_SIZE = 12

AES_MODES = ("gcm", "cbc")
KDFS = ("pbkdf2", "scrypt")
DES3_IV_SIZE = 8
KNOWN_ALGS = ("fernet", "aes-gcm", "aes-cbc", "des3-cbc")


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _derive_key(
    passphrase: str, salt: bytes, kdf: str, iterations: int, length: int = 32
) -> bytes:
    password = passphrase.encode("utf-8")
    if kdf == "pbkdf2":
        from Crypto.Hash import SHA256
        from Crypto.Protocol.KDF import PBKDF2

        return PBKDF2(
            password,
            salt,
            dkLen=length,
            count=iterations,
            hmac_hash_module=SHA256,
        )
    if kdf == "scrypt":
        from Crypto.Protocol.KDF import scrypt

        # n=2**14, r=8, p=1 is the common interactive setting.
        return scrypt(password, salt, key_len=length, N=2 ** 14, r=8, p=1)
    raise ValueError(f"unknown KDF: {kdf}")


def _derive_fernet_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def encrypt_fernet(plaintext: str, passphrase: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    salt = os.urandom(SALT_SIZE)
    key = _derive_fernet_key(passphrase, salt, iterations)
    token = Fernet(key).encrypt(plaintext.encode("utf-8")).decode("ascii")
    return pack({
        "v": 1,
        "alg": "fernet",
        "kdf": "pbkdf2",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "token": token,
    })


def encrypt_aes(
    plaintext: str,
    passphrase: str,
    mode: str = "gcm",
    kdf: str = "pbkdf2",
    iterations: int = DEFAULT_ITERATIONS,
) -> str:
    mode = mode.lower()
    kdf = kdf.lower()
    if mode not in AES_MODES:
        raise ValueError(f"AES mode must be one of {AES_MODES}")
    if kdf not in KDFS:
        raise ValueError(f"KDF must be one of {KDFS}")

    salt = os.urandom(SALT_SIZE)
    key = _derive_key(passphrase, salt, kdf, iterations)
    data = plaintext.encode("utf-8")

    if mode == "gcm":
        nonce = os.urandom(NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return pack({
            "v": 1,
            "alg": "aes-gcm",
            "kdf": kdf,
            "iterations": iterations,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        })

    iv = os.urandom(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return pack({
        "v": 1,
        "alg": "aes-cbc",
        "kdf": kdf,
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    })


def encrypt_des3(
    plaintext: str,
    passphrase: str,
    kdf: str = "pbkdf2",
    iterations: int = DEFAULT_ITERATIONS,
) -> str:
    """3DES-CBC with a passphrase.

    Included for legacy interoperability only: 3DES is obsolete and should
    not be used for new data. The construction matches AES-CBC (PBKDF2 or
    scrypt, random salt and IV, PKCS#7 padding).
    """
    kdf = kdf.lower()
    if kdf not in KDFS:
        raise ValueError(f"KDF must be one of {KDFS}")

    salt = os.urandom(SALT_SIZE)
    key = _derive_key(passphrase, salt, kdf, iterations, length=24)
    iv = os.urandom(DES3_IV_SIZE)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), DES3.block_size))
    return pack({
        "v": 1,
        "alg": "des3-cbc",
        "kdf": kdf,
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    })


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------

def _b64_field(payload, name: str) -> bytes:
    try:
        return base64.b64decode(payload[name])
    except (KeyError, TypeError, ValueError) as exc:
        raise ContainerError(f"container is missing or has a bad '{name}' field") from exc


def decrypt_fernet(token_text: str, passphrase: str) -> str:
    payload = unpack(token_text)
    if payload.get("alg") != "fernet":
        raise ContainerError("container is not Fernet")
    iterations = int(payload.get("iterations", DEFAULT_ITERATIONS))
    salt = _b64_field(payload, "salt")
    try:
        token = payload["token"].encode("ascii")
    except (KeyError, AttributeError) as exc:
        raise ContainerError("container has no Fernet token") from exc
    key = _derive_fernet_key(passphrase, salt, iterations)
    try:
        return Fernet(key).decrypt(token).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("wrong passphrase or corrupted Fernet token") from exc


def decrypt_aes(token_text: str, passphrase: str) -> str:
    payload = unpack(token_text)
    alg = payload.get("alg")
    if alg not in ("aes-gcm", "aes-cbc"):
        raise ContainerError("container is not AES")
    kdf = str(payload.get("kdf", "pbkdf2"))
    iterations = int(payload.get("iterations", DEFAULT_ITERATIONS))
    salt = _b64_field(payload, "salt")
    ciphertext = _b64_field(payload, "ciphertext")
    key = _derive_key(passphrase, salt, kdf, iterations)

    if alg == "aes-gcm":
        nonce = _b64_field(payload, "nonce")
        tag = _b64_field(payload, "tag")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            data = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as exc:
            raise ValueError("wrong passphrase or corrupted AES-GCM data") from exc
    else:
        iv = _b64_field(payload, "iv")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        try:
            data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except ValueError as exc:
            raise ValueError("wrong passphrase or corrupted AES-CBC data") from exc

    return data.decode("utf-8", errors="replace")


def decrypt_des3(token_text: str, passphrase: str) -> str:
    payload = unpack(token_text)
    if payload.get("alg") != "des3-cbc":
        raise ContainerError("container is not 3DES")
    kdf = str(payload.get("kdf", "pbkdf2"))
    iterations = int(payload.get("iterations", DEFAULT_ITERATIONS))
    salt = _b64_field(payload, "salt")
    iv = _b64_field(payload, "iv")
    ciphertext = _b64_field(payload, "ciphertext")
    key = _derive_key(passphrase, salt, kdf, iterations, length=24)
    try:
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        data = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    except ValueError as exc:
        raise ValueError("wrong passphrase or corrupted 3DES data") from exc
    return data.decode("utf-8", errors="replace")


def decrypt_modern(token_text: str, passphrase: str) -> str:
    payload = unpack(token_text)
    alg = payload.get("alg")
    if alg == "fernet":
        return decrypt_fernet(token_text, passphrase)
    if alg in ("aes-gcm", "aes-cbc"):
        return decrypt_aes(token_text, passphrase)
    if alg == "des3-cbc":
        return decrypt_des3(token_text, passphrase)
    raise ContainerError(f"unknown algorithm in container: {alg!r}")


def container_alg(token_text: str) -> Optional[str]:
    """Return the algorithm named inside a container, or ``None``."""
    try:
        return unpack(token_text).get("alg")
    except ContainerError:
        return None


def try_decrypt_any(token_text: str, passphrase: str):
    """Try ``passphrase`` against any supported container.

    Returns ``(plaintext, alg)`` when the container authenticates, else
    ``None``. Unlike :func:`try_decrypt` this also reports which algorithm
    was actually used.
    """
    alg = container_alg(token_text)
    if alg not in KNOWN_ALGS:
        return None
    try:
        return decrypt_modern(token_text, passphrase), alg
    except (ContainerError, ValueError, UnicodeDecodeError):
        return None


def try_decrypt(token_text: str, passphrase: str) -> Optional[str]:
    """Return the plaintext, or ``None`` if this passphrase is wrong."""
    try:
        return decrypt_modern(token_text, passphrase)
    except (ContainerError, ValueError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# Dictionary attack (the honest "no passphrase" mode for modern crypto)
# ---------------------------------------------------------------------------

def dictionary_attack(
    token_text: str,
    wordlist: Iterable[str],
    top: int = 5,
) -> List[Candidate]:
    """Try every passphrase in ``wordlist`` against a DecryptRE container."""
    if not is_container(token_text):
        return []
    try:
        alg = unpack(token_text).get("alg")
    except ContainerError:
        return []
    if alg not in KNOWN_ALGS:
        return []

    found: List[Candidate] = []
    seen = set()
    for passphrase in wordlist:
        passphrase = passphrase.strip()
        if not passphrase or passphrase in seen:
            continue
        seen.add(passphrase)
        plain = try_decrypt(token_text, passphrase)
        if plain is None:
            continue
        found.append(
            Candidate(
                plain,
                "modern",
                {"alg": alg, "passphrase": passphrase},
                score_text(plain),
                verified=True,
            )
        )
    found.sort(key=lambda c: c.score, reverse=True)
    return found[:top]


# ---------------------------------------------------------------------------
# Hash identification (one-way, never "decrypted")
# ---------------------------------------------------------------------------

_HASH_PATTERNS = (
    ("md5", 32, "0123456789abcdef"),
    ("sha1", 40, "0123456789abcdef"),
    ("sha256", 64, "0123456789abcdef"),
    ("sha512", 128, "0123456789abcdef"),
)


def identify_hash(text: str) -> List[str]:
    """Return likely hash algorithms for a hex-looking string."""
    cleaned = "".join(text.split()).lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned or any(ch not in "0123456789abcdef" for ch in cleaned):
        return []
    matches = [name for name, length, _ in _HASH_PATTERNS if len(cleaned) == length]
    if matches:
        return [f"{name} (one-way hash, cannot be decrypted)" for name in matches]
    if len(cleaned) % 2 == 0:
        return ["generic hex bytes (not necessarily a hash)"]
    return []


def hash_digest(text: str, algorithm: str = "sha256") -> str:
    """Hash helper used by examples and tests; hashing is not encryption."""
    return hashlib.new(algorithm, text.encode("utf-8")).hexdigest()
