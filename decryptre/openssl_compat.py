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
import concurrent.futures as futures
import hashlib
import multiprocessing
import os
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Tuple, Union

from Crypto.Cipher import AES, ARC4, DES, DES3
from Crypto.Util.Padding import unpad

from .models import Candidate
from .scorer import printable_ratio, score_text

try:  # cryptography >= 43 keeps these legacy ciphers in ``decrepit``.
    from cryptography.hazmat.decrepit.ciphers.algorithms import (
        CAST5 as _CAST5,
    )
    from cryptography.hazmat.decrepit.ciphers.algorithms import (
        Blowfish as _Blowfish,
    )
except ImportError:  # pragma: no cover - older cryptography releases
    try:
        from cryptography.hazmat.primitives.ciphers.algorithms import (
            CAST5 as _CAST5,
        )
        from cryptography.hazmat.primitives.ciphers.algorithms import (
            Blowfish as _Blowfish,
        )
    except ImportError:
        _Blowfish = _CAST5 = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
    from cryptography.hazmat.primitives.ciphers import modes as _modes
except ImportError:  # pragma: no cover - cryptography is a declared dependency
    _Cipher = _modes = None

MAGIC = b"Salted__"
SALT_SIZE = 8
PBKDF2_ITERATIONS = 10_000
PARALLEL_MIN_PASSPHRASES = 1000
PARALLEL_CHUNK_SIZE = 500
MAX_DEFAULT_WORKERS = 8


class OpenSSLError(ValueError):
    """Raised when a value is not a supported OpenSSL salted blob."""


class _CryptographyContext:
    """Minimal encrypt/decrypt wrapper around a cryptography CBC cipher.

    ``pycryptodome`` 4.5 removed its Blowfish and CAST classes, so those two
    ciphers come from ``cryptography``. The wrapped interface matches what the
    pycryptodome-based entries already provide.
    """

    def __init__(self, algorithm, iv: bytes) -> None:
        self._algorithm = algorithm
        self._iv = iv

    def encrypt(self, data: bytes) -> bytes:
        context = _Cipher(self._algorithm, _modes.CBC(self._iv)).encryptor()
        return context.update(data) + context.finalize()

    def decrypt(self, data: bytes) -> bytes:
        context = _Cipher(self._algorithm, _modes.CBC(self._iv)).decryptor()
        return context.update(data) + context.finalize()


def _pycryptodome_cbc(module):
    def make(key: bytes, iv: bytes):
        return module.new(key, module.MODE_CBC, iv)

    return make


def _cryptography_cbc(algorithm):
    def make(key: bytes, iv: bytes):
        return _CryptographyContext(algorithm(key), iv)

    return make


def _rc4(key: bytes, iv: bytes):
    return ARC4.new(key)


@dataclass(frozen=True)
class CipherSpec:
    """One OpenSSL cipher DecryptRE can read."""

    label: str
    make: Callable[[bytes, bytes], object]
    block_size: int
    key_length: int
    iv_length: int
    stream: bool = False


_CIPHERS: Tuple[CipherSpec, ...] = (
    CipherSpec("AES-256-CBC", _pycryptodome_cbc(AES), 16, 32, 16),
    CipherSpec("AES-192-CBC", _pycryptodome_cbc(AES), 16, 24, 16),
    CipherSpec("AES-128-CBC", _pycryptodome_cbc(AES), 16, 16, 16),
    CipherSpec("3DES-CBC", _pycryptodome_cbc(DES3), 8, 24, 8),
    CipherSpec("DES-CBC", _pycryptodome_cbc(DES), 8, 8, 8),
    CipherSpec("Blowfish-CBC", _cryptography_cbc(_Blowfish), 8, 16, 8)
    if _Blowfish
    else None,
    CipherSpec("CAST5-CBC", _cryptography_cbc(_CAST5), 8, 16, 8)
    if _CAST5
    else None,
    CipherSpec("RC4", _rc4, 1, 16, 0, stream=True),
)
_CIPHERS = tuple(spec for spec in _CIPHERS if spec is not None)


def available_ciphers() -> Tuple[str, ...]:
    """Cipher names this build can read, for help and error messages."""
    return tuple(spec.label for spec in _CIPHERS)


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
        # Files are read with surrogateescape, so raw binary blobs arrive as
        # surrogate code points. Recover the original bytes from them.
        try:
            raw_text = stripped.encode("utf-8", "surrogateescape")
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


def _evp_material(
    passphrase: bytes, salt: bytes, length: int, digest: str
) -> bytes:
    """EVP_BytesToKey material long enough to slice every cipher variant."""
    material = b""
    previous = b""
    while len(material) < length:
        previous = hashlib.new(digest, previous + passphrase + salt).digest()
        material += previous
    return material


def evp_bytes_to_key(
    passphrase: bytes,
    salt: bytes,
    key_length: int,
    iv_length: int,
    digest: str = "md5",
) -> Tuple[bytes, bytes]:
    """OpenSSL's EVP_BytesToKey (the KDF used without ``-pbkdf2``)."""
    material = _evp_material(
        passphrase, salt, key_length + iv_length, digest
    )
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
    body: bytes, key: bytes, iv: bytes, label: str, spec: CipherSpec
) -> Optional[Tuple[str, str]]:
    try:
        data = spec.make(key, iv).decrypt(body)
        if not spec.stream:
            data = unpad(data, spec.block_size)
    except (ValueError, TypeError):
        return None
    plain = _plaintext(data)
    return (plain, label) if plain is not None else None


def _fits(body: bytes, spec: CipherSpec) -> bool:
    return spec.stream or len(body) % spec.block_size == 0


def _legacy_ciphers(body: bytes) -> Tuple[CipherSpec, ...]:
    """Block ciphers used by guessing; RC4 is deliberately excluded."""
    return tuple(
        spec for spec in _CIPHERS if not spec.stream and _fits(body, spec)
    )


@dataclass(frozen=True)
class LegacyAttempt:
    """A parsed ``Salted__`` blob ready for repeated passphrase guesses.

    The base64 decoding and the cipher list are fixed once.  The
    incremental attack then runs the same MD5/SHA-256 legacy KDF sweep and
    cipher order as the wordlist path, without re-parsing the blob per
    guess.  RC4 is not included: its stream output has no padding or tag,
    so wrong keys too often look printable.
    """

    salt: bytes
    body: bytes
    ciphers: Tuple[CipherSpec, ...]
    digest: str
    material_length: int = 0

    def __post_init__(self) -> None:
        if not self.material_length and self.ciphers:
            object.__setattr__(
                self,
                "material_length",
                max(spec.key_length + spec.iv_length for spec in self.ciphers),
            )

    @property
    def variant_count(self) -> int:
        """Number of cipher/KDF decryptions tried per passphrase."""
        return 2 * len(self.ciphers)

    def try_digest(
        self, passphrase: Union[str, bytes], digest: str
    ) -> Optional[Tuple[str, str]]:
        """Try one password with one digest across every fixed cipher."""
        password = (
            passphrase.encode("utf-8")
            if isinstance(passphrase, str)
            else passphrase
        )
        ciphers = self.ciphers
        salt = self.salt
        body = self.body
        material = _evp_material(
            password, salt, self.material_length, digest
        )
        for spec in ciphers:
            key = material[:spec.key_length]
            iv = material[
                spec.key_length:spec.key_length + spec.iv_length
            ]
            hit = _decrypt_with(
                body,
                key,
                iv,
                f"OpenSSL {spec.label} ({digest.upper()})",
                spec,
            )
            if hit is not None:
                return hit
        return None

    def try_passphrase(
        self, passphrase: Union[str, bytes]
    ) -> Optional[Tuple[str, str]]:
        """Try one password with OpenSSL's legacy MD5 and SHA-256 KDFs."""
        for digest in ("md5", "sha256"):
            hit = self.try_digest(passphrase, digest)
            if hit is not None:
                return hit
        return None


def prepare_legacy_attempt(token_text: str) -> LegacyAttempt:
    """Parse a blob once and fix its block-cipher variants for guessing."""
    raw = _decode_payload(token_text)
    if raw is None:
        raise OpenSSLError("not an OpenSSL 'Salted__' blob")
    salt = raw[len(MAGIC):len(MAGIC) + SALT_SIZE]
    body = raw[len(MAGIC) + SALT_SIZE:]
    if len(salt) != SALT_SIZE or not body:
        raise OpenSSLError("truncated OpenSSL salted blob")
    return LegacyAttempt(
        salt=salt,
        body=body,
        ciphers=_legacy_ciphers(body),
        digest=hashlib.sha256(raw).hexdigest(),
    )


def default_workers() -> int:
    """A conservative default for explicit OpenSSL scan parallelism."""
    return max(1, min(MAX_DEFAULT_WORKERS, os.cpu_count() or 1))


_WORKER_ATTEMPT: Optional[LegacyAttempt] = None
_WORKER_STOP = None


def _parallel_worker_init(token_text: str, stop) -> None:
    """Build the parsed attempt once in each spawned worker."""
    global _WORKER_ATTEMPT, _WORKER_STOP
    _WORKER_ATTEMPT = prepare_legacy_attempt(token_text)
    _WORKER_STOP = stop


def _stopped(chunk_index: int, offset: int) -> bool:
    """Check the shared ordered-stop marker, throttled to every 16 items."""
    if offset & 15:
        return False
    marker = _WORKER_STOP.value
    return marker == -2 or (marker >= 0 and chunk_index > marker)


def _mark_hit(chunk_index: int) -> None:
    """Record the earliest chunk that found a hit and stop later chunks."""
    with _WORKER_STOP.get_lock():
        marker = _WORKER_STOP.value
        if marker != -2 and (marker < 0 or chunk_index < marker):
            _WORKER_STOP.value = chunk_index


def _dictionary_parallel_worker(payload):
    digest, chunk_index, passwords = payload
    for offset, password in enumerate(passwords):
        if _stopped(chunk_index, offset):
            return None
        hit = _WORKER_ATTEMPT.try_digest(password, digest)
        if hit is not None:
            _mark_hit(chunk_index)
            return chunk_index, offset, password, hit[0], hit[1]
    return None


def _incremental_parallel_worker(payload):
    chunk_index, charset, length, start, count = payload
    from .incremental import enumerate_passphrases

    for offset, passphrase in enumerate(
        enumerate_passphrases(charset, length, start)
    ):
        if offset >= count:
            break
        if _stopped(chunk_index, offset):
            return None
        hit = _WORKER_ATTEMPT.try_passphrase(passphrase)
        if hit is not None:
            _mark_hit(chunk_index)
            return chunk_index, passphrase, hit, offset + 1
    return None


def parallel_incremental_attack(
    token_text: str,
    state,
    state_path,
    workers: int,
    progress=None,
):
    """Run the generic parallel incremental engine on an OpenSSL blob."""
    from .incremental import parallel_incremental_attack as run

    return run(
        state,
        token_text,
        state_path,
        _parallel_worker_init,
        _incremental_parallel_worker,
        workers,
        progress=progress,
    )


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
        for spec in _CIPHERS:
            if not _fits(body, spec):
                continue
            key, iv = evp_bytes_to_key(
                password, salt, spec.key_length, spec.iv_length, digest
            )
            hit = _decrypt_with(
                body, key, iv, f"OpenSSL {spec.label} ({digest.upper()})", spec
            )
            if hit:
                return hit

    for spec in _CIPHERS:
        if not _fits(body, spec):
            continue
        key, iv = _pbkdf2_key(password, salt, spec.key_length, spec.iv_length)
        hit = _decrypt_with(
            body, key, iv, f"OpenSSL {spec.label} (PBKDF2-SHA256)", spec
        )
        if hit:
            return hit
    return None


def _dictionary_attack_parallel(
    token_text: str,
    passwords: List[bytes],
    total: int,
    top: int,
    progress: Optional[Callable[[int, int, str], None]],
    workers: int,
) -> List[Candidate]:
    """Run digest phases over ordered chunks in spawned worker processes."""
    chunks = [
        passwords[start:start + PARALLEL_CHUNK_SIZE]
        for start in range(0, total, PARALLEL_CHUNK_SIZE)
    ]
    starts = list(range(0, total, PARALLEL_CHUNK_SIZE))
    context = multiprocessing.get_context("spawn")
    stop = context.Value("i", -1)
    executor = futures.ProcessPoolExecutor(
        max_workers=min(workers, len(chunks)),
        mp_context=context,
        initializer=_parallel_worker_init,
        initargs=(token_text, stop),
    )
    jobs = []
    try:
        for digest, label in (("md5", "MD5"), ("sha256", "SHA-256")):
            stop.value = -1
            if progress:
                progress(0, total, label)
            jobs = [
                executor.submit(
                    _dictionary_parallel_worker,
                    (digest, index, chunk),
                )
                for index, chunk in enumerate(chunks)
            ]
            done = 0
            for index, (job, chunk) in enumerate(zip(jobs, chunks)):
                result = job.result()
                if result is None:
                    done += len(chunk)
                    if progress:
                        progress(min(done, total), total, label)
                    continue

                hit_chunk, offset, password, plain, alg = result
                if progress:
                    progress(
                        min(starts[hit_chunk] + offset + 1, total),
                        total,
                        label,
                    )
                for later in jobs[index + 1:]:
                    later.cancel()
                return [
                    Candidate(
                        plain,
                        "openssl",
                        {
                            "alg": alg,
                            "passphrase": password.decode("utf-8", "replace"),
                        },
                        score_text(plain),
                        verified=True,
                    )
                ][:top]
    except BaseException:
        stop.value = -2
        raise
    finally:
        for job in jobs:
            job.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
    return []


def dictionary_attack(
    token_text: str,
    wordlist: Iterable[str],
    top: int = 2,
    progress: Optional[Callable[[int, int, str], None]] = None,
    workers: int = 1,
) -> List[Candidate]:
    """Try a wordlist against an OpenSSL salted blob.

    The legacy KDF is cheap (no iteration count), so a bundled wordlist is
    practical here. The PBKDF2 variant is not wordlisted: at 10,000 iterations
    per guess it would turn seconds into minutes, so `--key` is required for
    those blobs.

    ``progress`` is called as ``progress(done, total, digest)`` while the scan
    runs, so a caller can show that work is happening instead of looking
    frozen.
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
    if not passwords:
        return []

    total = len(passwords)
    workers = max(1, workers)
    if workers > 1 and total >= PARALLEL_MIN_PASSPHRASES:
        return _dictionary_attack_parallel(
            token_text, passwords, total, top, progress, workers
        )

    step = max(1, total // 20)
    candidates = _legacy_ciphers(body)
    material_length = max(
        (spec.key_length + spec.iv_length for spec in candidates), default=0
    )

    # Fast path: EVP_BytesToKey with MD5 and SHA-256. RC4 is excluded: it is
    # a stream cipher with no padding or tag, so a wrong key produces
    # printable-looking output often enough to make wordlist hits meaningless.
    # It remains available with an explicit --key.
    for digest in ("md5", "sha256"):
        label = "MD5" if digest == "md5" else "SHA-256"
        if progress:
            progress(0, total, label)
        for index, password in enumerate(passwords, 1):
            material = _evp_material(
                password, salt, material_length, digest
            )
            for spec in candidates:
                key = material[:spec.key_length]
                iv = material[
                    spec.key_length:spec.key_length + spec.iv_length
                ]
                hit = _decrypt_with(
                    body,
                    key,
                    iv,
                    f"OpenSSL {spec.label} ({label})",
                    spec,
                )
                if hit:
                    plain, alg = hit
                    found.append(
                        Candidate(
                            plain,
                            "openssl",
                            {
                                "alg": alg,
                                "passphrase": password.decode("utf-8", "replace"),
                            },
                            score_text(plain),
                            verified=True,
                        )
                    )
                    if progress:
                        progress(index, total, label)
                    return found[:top]
            if progress and (index % step == 0 or index == total):
                progress(index, total, label)

    return found
