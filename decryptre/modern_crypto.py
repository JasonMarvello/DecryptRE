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
import multiprocessing
import os
import time
from collections import deque
from concurrent import futures
from typing import Callable, Iterable, Iterator, List, Optional, Tuple, Union

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad

from .containers import ContainerError, is_container, pack, unpack
from .models import Candidate
from .resources import lower_priority
from .scorer import score_text
from .wordlist import expansion_count, iter_expansions

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

PARALLEL_MIN_PASSPHRASES = 200
PARALLEL_CHUNK_SIZE = 64
RESULT_TARGET = 2


def _as_text(word: Union[str, bytes]) -> str:
    """Wordlist entries are bytes; decode only where a str is required."""
    if isinstance(word, bytes):
        return word.decode("utf-8", "replace")
    return str(word)


def _iter_chunks(
    candidates: Iterable[Union[str, bytes]], size: int = PARALLEL_CHUNK_SIZE
) -> Iterator[Tuple[str, ...]]:
    """Group a stream into bounded, stripped, non-empty chunks."""
    chunk: List[str] = []
    for word in candidates:
        passphrase = _as_text(word).strip()
        if not passphrase:
            continue
        chunk.append(passphrase)
        if len(chunk) >= size:
            yield tuple(chunk)
            chunk = []
    if chunk:
        yield tuple(chunk)


def _rank_candidates(found: List[Candidate], top: int) -> List[Candidate]:
    """Order by plaintext plausibility, keeping one entry per passphrase."""
    ranked = sorted(found, key=lambda candidate: candidate.score, reverse=True)
    unique: List[Candidate] = []
    seen = set()
    for candidate in ranked:
        passphrase = candidate.params.get("passphrase")
        if passphrase in seen:
            continue
        seen.add(passphrase)
        unique.append(candidate)
    return unique[:top]


def _candidate(passphrase: str, plain: str, alg: str) -> Candidate:
    return Candidate(
        plain,
        "modern",
        {"alg": alg, "passphrase": passphrase},
        score_text(plain),
        verified=True,
    )


def _result_target(top: int) -> int:
    """One authenticated hit proves the passphrase; two is already plenty."""
    return max(1, min(top, RESULT_TARGET))


def _dictionary_attack_serial(
    token_text: str,
    wordlist_factory: Callable[[], Iterable[Union[str, bytes]]],
    total: int,
    top: int,
    progress: Optional[Callable[[int, int, str], None]],
) -> List[Candidate]:
    """Stream a wordlist in this process; a verified hit ends the scan."""
    alg = container_alg(token_text) or "modern"
    target = _result_target(top)
    found: List[Candidate] = []
    for index, raw in enumerate(wordlist_factory(), start=1):
        passphrase = _as_text(raw).strip()
        if not passphrase:
            continue
        plain = try_decrypt(token_text, passphrase)
        if progress and (index % 500 == 0 or index >= total):
            progress(min(index, total), total, alg)
        if plain is not None:
            found.append(_candidate(passphrase, plain, alg))
            if len(found) >= target:
                break
    return _rank_candidates(found, top)


_WORKER_TOKEN: Optional[str] = None
_WORKER_ALG: Optional[str] = None
_WORKER_STOP = None


def _worker_init(token_text: str, stop, priority: str = "background") -> None:
    """Unpack the container once per worker and drop to background priority."""
    global _WORKER_TOKEN, _WORKER_ALG, _WORKER_STOP
    lower_priority(priority)
    _WORKER_TOKEN = token_text
    _WORKER_ALG = container_alg(token_text)
    _WORKER_STOP = stop


def _stopped(chunk_index: int, offset: int) -> bool:
    """Check the shared ordered-stop marker, throttled to every 16 guesses."""
    if offset & 15:
        return False
    return _WORKER_STOP.value >= 0 and chunk_index > _WORKER_STOP.value


def _mark_hit(chunk_index: int) -> None:
    """Record the earliest chunk that found a passphrase."""
    with _WORKER_STOP.get_lock():
        marker = _WORKER_STOP.value
        if marker < 0 or chunk_index < marker:
            _WORKER_STOP.value = chunk_index


def _chunk_worker(payload):
    """Try one chunk in a spawned worker and return its verified hits."""
    chunk_index, passwords = payload
    token_text = _WORKER_TOKEN
    alg = _WORKER_ALG or "modern"
    hits = []
    for offset, passphrase in enumerate(passwords):
        if _stopped(chunk_index, offset):
            break
        plain = try_decrypt(token_text, passphrase)
        if plain is None:
            continue
        _mark_hit(chunk_index)
        hits.append(_candidate(passphrase, plain, alg))
    return chunk_index, len(passwords), hits


def _dictionary_attack_parallel(
    token_text: str,
    wordlist_factory: Callable[[], Iterable[Union[str, bytes]]],
    total: int,
    top: int,
    progress: Optional[Callable[[int, int, str], None]],
    workers: int,
    priority: str = "background",
) -> List[Candidate]:
    """Scan a chunked stream in spawned workers; a hit stops later chunks."""
    alg = container_alg(token_text) or "modern"
    context = multiprocessing.get_context("spawn")
    stop = context.Value("i", -1)
    executor = futures.ProcessPoolExecutor(
        max_workers=max(1, workers),
        mp_context=context,
        initializer=_worker_init,
        initargs=(token_text, stop, priority),
    )
    found: List[Candidate] = []
    pending = deque()
    stream = _iter_chunks(wordlist_factory())
    next_index = 0
    done = 0

    def submit_one() -> bool:
        nonlocal next_index
        chunk = next(stream, None)
        if chunk is None:
            return False
        job = executor.submit(_chunk_worker, (next_index, chunk))
        pending.append((next_index, job))
        next_index += 1
        return True

    try:
        for _ in range(max(1, workers * 2)):
            if not submit_one():
                break
        while pending:
            index, job = pending.popleft()
            _chunk_index, processed, hits = job.result()
            done += processed
            if progress:
                progress(min(done, total), total, alg)
            marker = stop.value
            if marker < 0 or index <= marker:
                found.extend(hits)
            if found:
                break
            submit_one()
    finally:
        for _index, job in pending:
            job.cancel()
        executor.shutdown(wait=True)
    return _rank_candidates(found, top)


def estimate_attack_seconds(
    token_text: str, candidates: int, workers: int = 1
) -> float:
    """Time one real guess against this container, then scale it out.

    Modern containers pay a fixed KDF cost per guess, so a single probe is a
    faithful estimate; nothing here assumes a hard-coded speed.
    """
    # The first call also imports the cipher backends, so warm up once and time
    # the second one; otherwise the estimate is inflated by import cost.
    try_decrypt(token_text, "decryptre-timing-probe")
    started = time.monotonic()
    try_decrypt(token_text, "decryptre-timing-probe")
    per_guess = max(0.0005, time.monotonic() - started)
    return per_guess * max(0, candidates) / max(1, workers)


def dictionary_attack_stream(
    token_text: str,
    wordlist_factory: Callable[[], Iterable[Union[str, bytes]]],
    total: int,
    top: int = 5,
    progress: Optional[Callable[[int, int, str], None]] = None,
    workers: int = 1,
    priority: str = "background",
    case_variants: str = "off",
    mutations: str = "off",
) -> List[Candidate]:
    """Try a streamed wordlist against a DecryptRE container.

    ``wordlist_factory`` returns a fresh iterator so a tiered list is streamed
    instead of loaded into memory. One authenticating passphrase is proof, so
    the scan stops as soon as it finds one (or ``top`` when that is larger).
    """
    if not is_container(token_text):
        return []
    try:
        alg = unpack(token_text).get("alg")
    except ContainerError:
        return []
    if alg not in KNOWN_ALGS or total <= 0:
        return []
    if case_variants != "off" or mutations != "off":
        base_factory = wordlist_factory
        wordlist_factory = lambda: iter_expansions(  # noqa: E731
            base_factory(), case_variants, mutations
        )
    workers = max(1, workers)
    if workers > 1 and total >= PARALLEL_MIN_PASSPHRASES:
        return _dictionary_attack_parallel(
            token_text,
            wordlist_factory,
            total,
            top,
            progress,
            workers,
            priority,
        )
    return _dictionary_attack_serial(
        token_text, wordlist_factory, total, top, progress
    )


def dictionary_attack(
    token_text: str,
    wordlist: Iterable[Union[str, bytes]],
    top: int = 5,
    workers: int = 1,
    priority: str = "background",
    case_variants: str = "off",
    mutations: str = "off",
    progress: Optional[Callable[[int, int, str], None]] = None,
) -> List[Candidate]:
    """Try every passphrase in an in-memory ``wordlist`` against a container."""
    seen = set()
    words: List[str] = []
    for word in wordlist:
        passphrase = _as_text(word).strip()
        if not passphrase or passphrase in seen:
            continue
        seen.add(passphrase)
        words.append(passphrase)
    if not words:
        return []
    # iter_expansions works on the bytes a wordlist yields; encode the cleaned
    # passphrases back so ASCII mutation tails can be appended.
    frozen = tuple(passphrase.encode("utf-8") for passphrase in words)
    total = expansion_count(len(frozen), case_variants, mutations)
    return dictionary_attack_stream(
        token_text,
        lambda: iter(frozen),
        total,
        top=top,
        progress=progress,
        workers=workers,
        priority=priority,
        case_variants=case_variants,
        mutations=mutations,
    )


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
