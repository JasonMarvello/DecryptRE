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
from collections import deque
from itertools import islice
from dataclasses import dataclass
from functools import partial
from typing import Callable, Iterable, Iterator, List, Optional, Tuple, Union

from Crypto.Cipher import AES, ARC4, DES, DES3
from Crypto.Util.Padding import unpad

from .models import Candidate
from .resources import lower_priority
from .scorer import printable_ratio, score_text
from .wordlist import expansion_count, iter_expansions

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
# An OpenSSL blob does not record the digest or PBKDF2 iteration count, so a
# known passphrase is tried against the digests and cost settings `openssl
# enc` commonly uses.  Bulk guessing stays on MD5/SHA-256 for speed (those
# are the OpenSSL defaults across versions).
LEGACY_GUESS_DIGESTS = ("md5", "sha256")
KNOWN_LEGACY_DIGESTS = ("md5", "sha256", "sha1", "sha512", "sha224", "sha384")
PBKDF2_GUESS_DIGESTS = ("sha256", "sha1", "sha512")
PBKDF2_ITERATION_GUESSES = (10_000, 100_000)
_DIGEST_LABELS = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
}


def _digest_label(digest: str) -> str:
    return _DIGEST_LABELS.get(digest, digest.upper())
PARALLEL_MIN_PASSPHRASES = 1000
PARALLEL_CHUNK_SIZE = 500
# AES-256-CBC is the `openssl enc` default and the first candidates are the
# bundled common-password list, where most real hits live. Scanning that
# prefix with AES only is about four times cheaper per guess than trying every
# legacy cipher; the exhaustive passes that follow still cover everything.
AES_FIRST_PREFIX = 1_000_000
MAX_DEFAULT_WORKERS = 64
RESULT_TARGET = 2
PLAUSIBLE_SCORE = -15.0


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
    # A stream cipher can turn a one-byte body into any character; a single
    # printable byte is too weak to call a successful OpenSSL decryption.
    if len(text) < 2:
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


def _valid_padding_block(
    body: bytes, key: bytes, iv: bytes, spec: CipherSpec
) -> bool:
    """Test PKCS#7 padding by decrypting only the final block.

    A wrong passphrase fails padding on almost every guess, so decrypting
    the whole body first made every guess cost the full ciphertext. CBC
    decrypts each block independently given the previous ciphertext block,
    so the last block alone is enough to reject a wrong key.
    """
    if spec.stream:
        return True
    size = spec.block_size
    if len(body) < size or len(body) % size:
        return False
    last = body[-size:]
    previous = body[-2 * size:-size] if len(body) >= 2 * size else iv
    try:
        block = spec.make(key, previous).decrypt(last)
    except (ValueError, TypeError):
        return False
    pad = block[-1]
    if not 1 <= pad <= size:
        return False
    return pad == 1 or block[-pad:] == bytes([pad]) * pad


def _decrypt_with(
    body: bytes, key: bytes, iv: bytes, label: str, spec: CipherSpec
) -> Optional[Tuple[str, str]]:
    if not _valid_padding_block(body, key, iv, spec):
        return None
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

    @property
    def aes_ciphers(self) -> Tuple[CipherSpec, ...]:
        """The AES variants, which `openssl enc` uses by default."""
        return tuple(
            spec for spec in self.ciphers if spec.label.startswith("AES-")
        )

    def try_digest(
        self,
        passphrase: Union[str, bytes],
        digest: str,
        ciphers: Optional[Tuple[CipherSpec, ...]] = None,
    ) -> Optional[Tuple[str, str]]:
        """Try one password with one digest across every fixed cipher."""
        password = (
            passphrase.encode("utf-8")
            if isinstance(passphrase, str)
            else passphrase
        )
        if ciphers is None:
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


def _available_cpus() -> int:
    """CPUs this process may actually use, respecting Linux affinity masks."""
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count() or 1


def default_workers() -> int:
    """Use the CPUs available to this process, with a sane upper bound."""
    return max(1, min(MAX_DEFAULT_WORKERS, _available_cpus()))


_WORKER_ATTEMPT: Optional[LegacyAttempt] = None
_WORKER_STOP = None


def _parallel_worker_init(
    token_text: str, stop, priority: str = "background"
) -> None:
    """Build the parsed attempt once in each spawned worker."""
    global _WORKER_ATTEMPT, _WORKER_STOP
    lower_priority(priority)
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


def _dictionary_worker_init(
    token_text: str, priority: str = "background"
) -> None:
    global _WORKER_ATTEMPT
    lower_priority(priority)
    _WORKER_ATTEMPT = prepare_legacy_attempt(token_text)


def _dictionary_parallel_worker(payload):
    """Scan a whole chunk and return every plausible hit in it."""
    digest, chunk_index, passwords, aes_only = payload
    attempt = _WORKER_ATTEMPT
    ciphers = attempt.aes_ciphers if aes_only else attempt.ciphers
    try_digest = attempt.try_digest
    hits = []
    for password in passwords:
        hit = try_digest(password, digest, ciphers)
        if hit is None:
            continue
        candidate = _candidate_for_hit(password, hit[0], hit[1])
        if candidate is not None:
            hits.append(candidate)
    return chunk_index, len(passwords), hits


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
    priority: str = "background",
):
    """Run the generic parallel incremental engine on an OpenSSL blob."""
    from .incremental import parallel_incremental_attack as run

    return run(
        state,
        token_text,
        state_path,
        partial(_parallel_worker_init, priority=priority),
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
    material_length = max(
        (spec.key_length + spec.iv_length for spec in _CIPHERS), default=0
    )

    for digest in KNOWN_LEGACY_DIGESTS:
        material = _evp_material(password, salt, material_length, digest)
        for spec in _CIPHERS:
            if not _fits(body, spec):
                continue
            key = material[:spec.key_length]
            iv = material[
                spec.key_length:spec.key_length + spec.iv_length
            ]
            hit = _decrypt_with(
                body,
                key,
                iv,
                f"OpenSSL {spec.label} ({_digest_label(digest)})",
                spec,
            )
            if hit:
                return hit

    # PBKDF2 blobs do not store the iteration count or digest either. Try the
    # OpenSSL default first, then the count used by common guides. Keeping
    # this list short matters: every wrong passphrase pays for all of it.
    for iterations in PBKDF2_ITERATION_GUESSES:
        for digest in PBKDF2_GUESS_DIGESTS:
            material = hashlib.pbkdf2_hmac(
                digest, password, salt, iterations, material_length
            )
            for spec in _CIPHERS:
                if not _fits(body, spec):
                    continue
                key = material[:spec.key_length]
                iv = material[
                    spec.key_length:spec.key_length + spec.iv_length
                ]
                label = (
                    f"OpenSSL {spec.label} "
                    f"(PBKDF2-{_digest_label(digest)}, {iterations} iterations)"
                )
                hit = _decrypt_with(body, key, iv, label, spec)
                if hit:
                    return hit
    return None


def _as_passphrase_bytes(word: Union[str, bytes]) -> bytes:
    """Keep wordlist entries as bytes; decode only for display."""
    return word if isinstance(word, bytes) else word.encode("utf-8")


def _iter_chunks(
    wordlist: Iterable[Union[str, bytes]],
    size: int = PARALLEL_CHUNK_SIZE,
) -> Iterator[List[bytes]]:
    """Group a stream into bounded chunks without materialising it."""
    chunk: List[bytes] = []
    for word in wordlist:
        password = _as_passphrase_bytes(word)
        if not password:
            continue
        chunk.append(password)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def is_plausible_plaintext(text: str) -> bool:
    """Reject padding-valid garbage before it is presented as a match."""
    stripped = text.strip()
    if len(stripped) < 2:
        return False
    letters = sum(1 for ch in stripped if ch.isalpha())
    if letters < 2:
        return False
    score = score_text(text)
    if score >= PLAUSIBLE_SCORE:
        return True
    # The English model cannot judge Cyrillic, CJK and similar scripts; a
    # legible non-Latin string still gets through the generic printable check.
    return score >= -18.0 and any(ord(ch) > 0x024F for ch in stripped)


def _candidate_for_hit(
    password: bytes, plain: str, alg: str
) -> Optional[Candidate]:
    if not is_plausible_plaintext(plain):
        return None
    return Candidate(
        plain,
        "openssl",
        {
            "alg": alg,
            "passphrase": password.decode("utf-8", "replace"),
        },
        score_text(plain),
        verified=True,
    )


def _result_target(top: int) -> int:
    """Collect up to two plausible results unless the caller asked for one."""
    return max(1, min(top, RESULT_TARGET))


def _rank_candidates(candidates: List[Candidate], top: int) -> List[Candidate]:
    return sorted(candidates, key=lambda item: item.score, reverse=True)[:top]


def _add_candidate(
    matches: List[Candidate],
    seen: set,
    candidate: Optional[Candidate],
) -> bool:
    if candidate is None:
        return False
    signature = candidate.signature()
    if signature in seen:
        return False
    seen.add(signature)
    matches.append(candidate)
    return True


def _scan_phases(
    attempt: LegacyAttempt, total: int
) -> Iterator[Tuple[str, str, Optional[Tuple[CipherSpec, ...]], int]]:
    """Yield ``(digest, label, aes_ciphers_or_None, limit)`` scan phases.

    AES-only phases run over the common prefix first, where a real passphrase
    is most likely to appear; the later all-cipher phases keep full coverage
    of the legacy ciphers and the rest of the list.
    """
    aes = attempt.aes_ciphers
    if aes:
        limit = min(total, AES_FIRST_PREFIX)
        for digest in LEGACY_GUESS_DIGESTS:
            yield digest, f"{_digest_label(digest)} \u00b7 AES first", aes, limit
    for digest in LEGACY_GUESS_DIGESTS:
        yield digest, _digest_label(digest), None, total


def _dictionary_attack_parallel(
    attempt: LegacyAttempt,
    token_text: str,
    wordlist_factory: Callable[[], Iterable[Union[str, bytes]]],
    total: int,
    top: int,
    progress: Optional[Callable[[int, int, str], None]],
    workers: int,
    priority: str = "background",
) -> List[Candidate]:
    """Run digest/cipher phases over a streamed wordlist in spawned workers.

    A few chunks are in flight at once. Workers return every plausible hit in
    their chunk, and the parent keeps scanning until two results or the tier is
    exhausted. Results are ranked by text score rather than chunk order.
    """
    target = _result_target(top)
    matches: List[Candidate] = []
    seen = set()
    context = multiprocessing.get_context("spawn")
    executor = futures.ProcessPoolExecutor(
        max_workers=max(1, workers),
        mp_context=context,
        initializer=_dictionary_worker_init,
        initargs=(token_text, priority),
    )
    pending = deque()
    try:
        for digest, label, aes_ciphers, limit in _scan_phases(attempt, total):
            pending.clear()
            if progress:
                progress(0, limit, label)
            stream = _iter_chunks(islice(wordlist_factory(), limit))
            next_index = 0
            done = 0
            aes_only = aes_ciphers is not None

            def submit_one() -> bool:
                nonlocal next_index
                try:
                    chunk = next(stream)
                except StopIteration:
                    return False
                job = executor.submit(
                    _dictionary_parallel_worker,
                    (digest, next_index, chunk, aes_only),
                )
                pending.append((next_index, len(chunk), job))
                next_index += 1
                return True

            for _ in range(max(1, workers * 2)):
                if not submit_one():
                    break

            while pending:
                _chunk_index, size, job = pending.popleft()
                _chunk, processed, hits = job.result()
                done += processed
                for candidate in hits:
                    _add_candidate(matches, seen, candidate)
                if progress:
                    progress(min(done, limit), limit, label)
                if len(matches) >= target:
                    for _index, _size, later in pending:
                        later.cancel()
                    return _rank_candidates(matches, top)
                submit_one()
    finally:
        for _index, _size, job in pending:
            job.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
    return _rank_candidates(matches, top)


def _dictionary_attack_serial(
    attempt: LegacyAttempt,
    wordlist_factory: Callable[[], Iterable[Union[str, bytes]]],
    total: int,
    top: int,
    progress: Optional[Callable[[int, int, str], None]],
) -> List[Candidate]:
    body = attempt.body
    material_length = max(
        (spec.key_length + spec.iv_length for spec in attempt.ciphers),
        default=0,
    )

    # Fast path: EVP_BytesToKey with MD5 and SHA-256. RC4 is excluded: it is
    # a stream cipher with no padding or tag, so a wrong key produces
    # printable-looking output often enough to make wordlist hits meaningless.
    # It remains available with an explicit --key.
    target = _result_target(top)
    matches: List[Candidate] = []
    seen = set()
    for digest, label, aes_ciphers, limit in _scan_phases(attempt, total):
        ciphers = aes_ciphers or attempt.ciphers
        digest_label = _digest_label(digest)
        step = max(1, limit // 20)
        if progress:
            progress(0, limit, label)
        for index, word in enumerate(wordlist_factory(), 1):
            if index > limit:
                break
            password = _as_passphrase_bytes(word)
            if not password:
                continue
            material = _evp_material(
                password, attempt.salt, material_length, digest
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
                    f"OpenSSL {spec.label} ({digest_label})",
                    spec,
                )
                if hit:
                    candidate = _candidate_for_hit(password, hit[0], hit[1])
                    _add_candidate(matches, seen, candidate)
                    if len(matches) >= target:
                        if progress:
                            progress(min(index, limit), limit, label)
                        return _rank_candidates(matches, top)
            if progress and (index % step == 0 or index >= limit):
                progress(min(index, limit), limit, label)
    return _rank_candidates(matches, top)


def dictionary_attack_stream(
    token_text: str,
    wordlist_factory: Callable[[], Iterable[Union[str, bytes]]],
    total: int,
    top: int = 2,
    progress: Optional[Callable[[int, int, str], None]] = None,
    workers: int = 1,
    priority: str = "background",
    case_variants: str = "off",
    case_variant_prefix: Optional[int] = None,
    mutations: str = "off",
) -> List[Candidate]:
    """Try a streamed wordlist against an OpenSSL salted blob.

    ``wordlist_factory`` is called once per digest/cipher phase, so tiered
    files are reopened instead of kept in memory. ``total`` is the number of
    candidates from the manifest (or a counted custom file) and is used for
    progress.
    """
    try:
        attempt = prepare_legacy_attempt(token_text)
    except OpenSSLError:
        return []
    if total <= 0:
        return []
    if case_variants != "off" or mutations != "off":
        base_factory = wordlist_factory
        wordlist_factory = lambda: iter_expansions(  # noqa: E731
            base_factory(), case_variants, mutations, case_variant_prefix
        )
    workers = max(1, workers)
    if workers > 1 and total >= PARALLEL_MIN_PASSPHRASES:
        return _dictionary_attack_parallel(
            attempt,
            token_text,
            wordlist_factory,
            total,
            top,
            progress,
            workers,
            priority,
        )
    return _dictionary_attack_serial(
        attempt, wordlist_factory, total, top, progress
    )


def dictionary_attack(
    token_text: str,
    wordlist: Iterable[Union[str, bytes]],
    top: int = 2,
    progress: Optional[Callable[[int, int, str], None]] = None,
    workers: int = 1,
    priority: str = "background",
    case_variants: str = "off",
    mutations: str = "off",
) -> List[Candidate]:
    """Try an in-memory wordlist against an OpenSSL salted blob.

    This compatibility wrapper de-duplicates an arbitrary iterable. The CLI
    uses :func:`dictionary_attack_stream` so bundled lists never accumulate in
    memory.
    """
    seen = set()
    passwords: List[bytes] = []
    for word in wordlist:
        password = _as_passphrase_bytes(word).strip()
        if password and password not in seen:
            seen.add(password)
            passwords.append(password)
    if not passwords:
        return []
    frozen = tuple(passwords)
    total = expansion_count(len(frozen), case_variants, mutations)
    return dictionary_attack_stream(
        token_text,
        lambda: iter(frozen),
        total,
        case_variants=case_variants,
        mutations=mutations,
        top=top,
        progress=progress,
        workers=workers,
        priority=priority,
    )
