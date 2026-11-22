"""Incremental (mask-style) passphrase search.

This module is deliberately separate from the wordlist attack in
:mod:`decryptre.openssl_compat`.  It enumerates every candidate of a chosen
charset, starting at ``min_length`` and working up to ``max_length``, in a
fixed order.  There is no randomness, no mutation and no duplicate
candidate.  "Exhaustive" means exhaustive *inside those bounds*: the search
is exponential and cannot find a passphrase outside the charset or length
range.

Callers provide ``attempt(passphrase)``, which tries one candidate against
the target.  :mod:`decryptre.openssl_compat` supplies that function for
OpenSSL ``Salted__`` blobs.  Keeping the driver generic means a future
unauthenticated format can reuse it without touching this enumeration code.
"""

import concurrent.futures as futures
import json
import multiprocessing
import os
import string
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterator, Optional, Sequence, Tuple

CHARSETS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": string.punctuation,
}
CHARSET_ORDER = ("lower", "upper", "digits", "symbols")
DEFAULT_CHARSETS = ("lower", "upper", "digits")
DEFAULT_MIN_LENGTH = 1
DEFAULT_MAX_LENGTH = 5
MAX_LENGTH_WITHOUT_OVERRIDE = 6
CONFIRM_THRESHOLD_SECONDS = 600.0
STATE_VERSION = 1
DEFAULT_CHECKPOINT_SECONDS = 5.0
DEFAULT_CHECKPOINT_ATTEMPTS = 4096
PARALLEL_MIN_PASSPHRASES = 1000
PARALLEL_CHUNK_SIZE = 500


def resolve_charset(names: Optional[Sequence[str]]) -> str:
    """Return the ordered, de-duplicated character set for ``names``."""
    selected = set(names or DEFAULT_CHARSETS)
    unknown = selected.difference(set(CHARSET_ORDER) | {"all"})
    if unknown:
        raise ValueError(
            "unknown charset component: " + ", ".join(sorted(unknown))
        )
    if "all" in selected:
        selected = set(CHARSET_ORDER)

    characters = []
    seen = set()
    for name in CHARSET_ORDER:
        if name not in selected:
            continue
        for char in CHARSETS[name]:
            if char not in seen:
                seen.add(char)
                characters.append(char)
    if not characters:
        raise ValueError("charset must contain at least one character")
    return "".join(characters)


def validate_lengths(min_length: int, max_length: int, allow_risky: bool) -> None:
    """Reject impossible ranges and lengths above the safe cap."""
    if min_length < 1:
        raise ValueError("--min-length must be at least 1")
    if max_length < min_length:
        raise ValueError("--max-length must be at least --min-length")
    if max_length > MAX_LENGTH_WITHOUT_OVERRIDE and not allow_risky:
        raise ValueError(
            f"--max-length {max_length} is above the safe cap of "
            f"{MAX_LENGTH_WITHOUT_OVERRIDE}; add --i-understand-the-risk "
            "to continue"
        )


def count_passphrases(charset: str, min_length: int, max_length: int) -> int:
    """Count every candidate from ``min_length`` through ``max_length``."""
    if min_length < 1:
        raise ValueError("min_length must be at least 1")
    if max_length < min_length:
        raise ValueError("max_length must be at least min_length")
    if not charset:
        raise ValueError("charset must contain at least one character")
    size = len(charset)
    return sum(size ** length for length in range(min_length, max_length + 1))


def count_remaining(
    charset: str,
    min_length: int,
    max_length: int,
    next_length: int,
    skip: int,
) -> int:
    """Count candidates left from a saved position to the end."""
    if next_length > max_length:
        return 0
    size = len(charset)
    total = size ** next_length - skip
    if total < 0:
        raise ValueError("checkpoint position is outside its length")
    for length in range(next_length + 1, max_length + 1):
        total += size ** length
    return total


def estimate_seconds(passphrases: int, rate: float) -> float:
    """Estimate wall-clock seconds from a measured passphrase rate."""
    if passphrases < 0:
        raise ValueError("passphrases must not be negative")
    if rate <= 0:
        raise ValueError("rate must be positive")
    try:
        return passphrases / rate
    except OverflowError:  # pragma: no cover - absurd --max-length values
        return float("inf")


def format_duration(seconds: float) -> str:
    """Human-readable duration that stays readable for huge estimates."""
    if seconds < 0:
        raise ValueError("seconds must not be negative")
    if seconds == float("inf"):
        return "effectively forever"
    if seconds < 0.01:
        return "<0.01 seconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 365.25:
        return f"{days:.1f} days"
    years = days / 365.25
    if years > 1_000_000_000_000:
        return "effectively forever"
    return f"{years:,.1f} years"


def enumerate_passphrases(charset: str, length: int, start: int = 0) -> Iterator[str]:
    """Yield candidates in ``itertools.product`` order, beginning at ``start``.

    The start position is converted directly to an odometer tuple, so a
    resumed length does not re-walk every earlier candidate.
    """
    if length < 1:
        raise ValueError("length must be at least 1")
    if not charset:
        raise ValueError("charset must contain at least one character")
    size = len(charset)
    total = size ** length
    if start < 0 or start > total:
        raise ValueError("start is outside this length")
    if start == total:
        return

    digits = [0] * length
    value = start
    for position in range(length - 1, -1, -1):
        digits[position] = value % size
        value //= size

    while True:
        yield "".join(charset[digit] for digit in digits)
        position = length - 1
        while position >= 0 and digits[position] == size - 1:
            digits[position] = 0
            position -= 1
        if position < 0:
            return
        digits[position] += 1


@dataclass
class SearchState:
    """Search progress and configuration, safe to write to disk.

    The state stores only positions and settings: never a passphrase or any
    plaintext.  ``next_length`` is the length currently being searched and
    ``skip`` is the number of candidates already completed at that length.
    """

    blob_digest: str
    charset: str
    min_length: int
    max_length: int
    variants: int
    next_length: int
    skip: int
    passphrases_done: int
    complete: bool = False
    version: int = STATE_VERSION

    @classmethod
    def create(
        cls,
        blob_digest: str,
        charset: str,
        min_length: int,
        max_length: int,
        variants: int,
    ) -> "SearchState":
        return cls(
            blob_digest=blob_digest,
            charset=charset,
            min_length=min_length,
            max_length=max_length,
            variants=variants,
            next_length=min_length,
            skip=0,
            passphrases_done=0,
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "blob_digest": self.blob_digest,
            "charset": self.charset,
            "min_length": self.min_length,
            "max_length": self.max_length,
            "variants": self.variants,
            "next_length": self.next_length,
            "skip": self.skip,
            "passphrases_done": self.passphrases_done,
            "complete": self.complete,
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "SearchState":
        required = (
            "version",
            "blob_digest",
            "charset",
            "min_length",
            "max_length",
            "variants",
            "next_length",
            "skip",
            "passphrases_done",
            "complete",
        )
        missing = [key for key in required if key not in payload]
        if missing:
            raise ValueError("checkpoint is missing: " + ", ".join(missing))
        try:
            state = cls(
                version=int(payload["version"]),
                blob_digest=str(payload["blob_digest"]),
                charset=str(payload["charset"]),
                min_length=int(payload["min_length"]),
                max_length=int(payload["max_length"]),
                variants=int(payload["variants"]),
                next_length=int(payload["next_length"]),
                skip=int(payload["skip"]),
                passphrases_done=int(payload["passphrases_done"]),
                complete=bool(payload["complete"]),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid checkpoint: {exc}")
        if state.version != STATE_VERSION:
            raise ValueError(f"unsupported checkpoint version: {state.version}")
        if not state.charset:
            raise ValueError("checkpoint charset is empty")
        if state.min_length < 1:
            raise ValueError("checkpoint min_length is invalid")
        if state.max_length < state.min_length:
            raise ValueError("checkpoint max_length is invalid")
        if state.variants < 1:
            raise ValueError("checkpoint variant count is invalid")
        if state.skip < 0 or state.passphrases_done < 0:
            raise ValueError("checkpoint position is invalid")
        if not state.complete and not (
            state.min_length <= state.next_length <= state.max_length
        ):
            raise ValueError("checkpoint next_length is outside its range")
        return state

    def _normalise(self) -> None:
        """Advance an exact length boundary and reject impossible positions."""
        if self.complete:
            return
        size = len(self.charset)
        while (
            self.next_length <= self.max_length
            and self.skip == size ** self.next_length
        ):
            self.next_length += 1
            self.skip = 0
        if self.next_length > self.max_length:
            self.complete = True
        elif self.skip > size ** self.next_length:
            raise ValueError("checkpoint position is outside its length")

    def save(self, path: Path) -> None:
        """Atomically write the checkpoint, readable only by the owner."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(self.to_dict(), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)

    @classmethod
    def load(cls, path: Path) -> "SearchState":
        path = Path(path)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            raise ValueError(f"cannot read checkpoint {path}: {exc}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"checkpoint {path} is not valid JSON: {exc}")
        if not isinstance(payload, dict):
            raise ValueError("checkpoint must contain a JSON object")
        state = cls.from_dict(payload)
        state._normalise()
        return state


def default_state_path(blob_digest: str) -> Path:
    """Per-blob checkpoint path, small and independent of the input file."""
    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        base = Path(state_home) / "decryptre"
    else:
        base = Path.home() / ".decryptre"
    return base / "incremental" / f"incremental-{blob_digest[:16]}.json"


def validate_resume(state: SearchState, blob_digest: str, variants: int) -> None:
    """Refuse to resume a checkpoint that belongs to another search."""
    if state.blob_digest != blob_digest:
        raise ValueError(
            "checkpoint belongs to a different blob; start a fresh run"
        )
    if state.variants != variants:
        raise ValueError(
            "the cipher/KDF variant set changed since the checkpoint; "
            "start over"
        )


@dataclass(frozen=True)
class RateMeasurement:
    passphrases_per_second: float
    samples: int
    seconds: float


def measure_rate(
    attempt: Callable[[str], Optional[object]],
    sample_target: int = 200,
    min_seconds: float = 0.05,
    max_samples: int = 5000,
) -> RateMeasurement:
    """Time full passphrase sweeps on this machine.

    The dummy strings contain a non-ASCII character, so they cannot collide
    with any of the ASCII charsets the tool supports.  Their results are
    intentionally ignored: this is a speed measurement, not a search.
    """
    target = min(max_samples, max(1, sample_target))
    samples = 0
    start = time.perf_counter()
    while samples < max_samples:
        while samples < target:
            attempt(f"\u00b5calibration-{samples}")
            samples += 1
        elapsed = time.perf_counter() - start
        if elapsed >= min_seconds or samples >= max_samples:
            break
        target = min(max_samples, target * 4)
    elapsed = max(time.perf_counter() - start, 1e-9)
    return RateMeasurement(samples / elapsed, samples, elapsed)


@dataclass(frozen=True)
class SearchProgress:
    length: int
    position: int
    length_total: int
    passphrases_done: int
    total_passphrases: int
    remaining: int
    rate: float
    eta_seconds: float


def incremental_attack(
    state: SearchState,
    attempt: Callable[[str], Optional[object]],
    state_path: Path,
    progress: Optional[Callable[[SearchProgress], None]] = None,
    checkpoint_seconds: float = DEFAULT_CHECKPOINT_SECONDS,
    checkpoint_attempts: int = DEFAULT_CHECKPOINT_ATTEMPTS,
) -> Optional[Tuple[str, object]]:
    """Search from ``state`` until a hit or the space is exhausted.

    Returns ``(passphrase, result)`` and marks the state complete on a hit,
    or ``None`` after exhausting every candidate.  Interruptions propagate
    after the current position is checkpointed, so ``--resume`` can continue
    without repeating completed work.
    """
    state_path = Path(state_path)
    charset = state.charset
    size = len(charset)
    total_passphrases = count_passphrases(
        charset, state.min_length, state.max_length
    )
    initial_done = state.passphrases_done
    started = time.monotonic()
    last_checkpoint = started
    since_checkpoint = 0
    state._normalise()

    def report(length: int, position: int, length_total: int) -> None:
        if progress is None:
            return
        elapsed = max(time.monotonic() - started, 1e-9)
        rate = max(0.0, (state.passphrases_done - initial_done) / elapsed)
        remaining = count_remaining(
            charset,
            state.min_length,
            state.max_length,
            state.next_length,
            state.skip,
        )
        eta = (
            estimate_seconds(remaining, rate)
            if rate > 0
            else float("inf")
        )
        progress(
            SearchProgress(
                length=length,
                position=position,
                length_total=length_total,
                passphrases_done=state.passphrases_done,
                total_passphrases=total_passphrases,
                remaining=remaining,
                rate=rate,
                eta_seconds=eta,
            )
        )

    try:
        for length in range(state.next_length, state.max_length + 1):
            skip = state.skip if length == state.next_length else 0
            state.next_length = length
            state.skip = skip
            position = skip
            length_total = size ** length

            for passphrase in enumerate_passphrases(charset, length, start=skip):
                hit = attempt(passphrase)
                position += 1
                state.skip = position
                state.passphrases_done += 1
                since_checkpoint += 1

                if hit is not None:
                    state.complete = True
                    state.save(state_path)
                    return passphrase, hit

                if since_checkpoint >= checkpoint_attempts or (
                    since_checkpoint % 16 == 0
                    and time.monotonic() - last_checkpoint >= checkpoint_seconds
                ):
                    state.save(state_path)
                    since_checkpoint = 0
                    last_checkpoint = time.monotonic()
                    report(length, position, length_total)

            state.next_length = length + 1
            state.skip = 0
            state.save(state_path)
            since_checkpoint = 0
            last_checkpoint = time.monotonic()
            report(length, length_total, length_total)

        state.complete = True
        state.next_length = state.max_length + 1
        state.skip = 0
        state.save(state_path)
        return None
    finally:
        if not state.complete:
            state.save(state_path)


def parallel_incremental_attack(
    state: SearchState,
    token_text: str,
    state_path: Path,
    initializer: Callable,
    worker: Callable,
    workers: int,
    progress: Optional[Callable[[SearchProgress], None]] = None,
    checkpoint_seconds: float = DEFAULT_CHECKPOINT_SECONDS,
    checkpoint_attempts: int = DEFAULT_CHECKPOINT_ATTEMPTS,
    chunk_size: int = PARALLEL_CHUNK_SIZE,
) -> Optional[Tuple[str, object]]:
    """Search ordered chunks in spawned workers and checkpoint a prefix.

    Results are consumed in chunk order, so a hit is still the first hit in
    the documented enumeration order. Later chunks stop as soon as an earlier
    chunk reports one, but earlier chunks are allowed to finish. The saved
    ``skip`` position therefore only covers completed contiguous work.
    """
    state_path = Path(state_path)
    workers = max(1, int(workers))
    chunk_size = max(1, int(chunk_size))
    state._normalise()
    if state.complete:
        return None

    charset = state.charset
    size = len(charset)
    total_passphrases = count_passphrases(
        charset, state.min_length, state.max_length
    )
    initial_done = state.passphrases_done
    started = time.monotonic()
    last_checkpoint = started
    since_checkpoint = 0

    def report(length: int, position: int, length_total: int) -> None:
        if progress is None:
            return
        elapsed = max(time.monotonic() - started, 1e-9)
        rate = max(0.0, (state.passphrases_done - initial_done) / elapsed)
        remaining = count_remaining(
            charset,
            state.min_length,
            state.max_length,
            state.next_length,
            state.skip,
        )
        eta = (
            estimate_seconds(remaining, rate)
            if rate > 0
            else float("inf")
        )
        progress(
            SearchProgress(
                length=length,
                position=position,
                length_total=length_total,
                passphrases_done=state.passphrases_done,
                total_passphrases=total_passphrases,
                remaining=remaining,
                rate=rate,
                eta_seconds=eta,
            )
        )

    chunks = []
    for length in range(state.next_length, state.max_length + 1):
        length_total = size ** length
        start = state.skip if length == state.next_length else 0
        for chunk_start in range(start, length_total, chunk_size):
            chunks.append(
                (
                    len(chunks),
                    length,
                    chunk_start,
                    min(chunk_size, length_total - chunk_start),
                    length_total,
                )
            )
    if not chunks:
        state.complete = True
        state.next_length = state.max_length + 1
        state.skip = 0
        state.save(state_path)
        return None

    context = multiprocessing.get_context("spawn")
    stop = context.Value("i", -1)
    executor = futures.ProcessPoolExecutor(
        max_workers=min(workers, len(chunks)),
        mp_context=context,
        initializer=initializer,
        initargs=(token_text, stop),
    )
    jobs = []
    try:
        jobs = [
            executor.submit(
                worker, (chunk_id, charset, length, start, count)
            )
            for chunk_id, length, start, count, _length_total in chunks
        ]
        for index, (job, chunk) in enumerate(zip(jobs, chunks)):
            chunk_id, length, start, count, length_total = chunk
            result = job.result()
            if result is not None:
                _chunk_id, passphrase, hit, completed = result
                state.passphrases_done += completed
                state.next_length = length
                state.skip = start + completed
                state.complete = True
                state.save(state_path)
                for later in jobs[index + 1:]:
                    later.cancel()
                return passphrase, hit

            state.passphrases_done += count
            state.next_length = length
            state.skip = start + count
            since_checkpoint += count
            if state.skip == length_total:
                state.next_length = length + 1
                state.skip = 0
                state.save(state_path)
                since_checkpoint = 0
                last_checkpoint = time.monotonic()
                report(length, length_total, length_total)
            elif since_checkpoint >= checkpoint_attempts or (
                since_checkpoint % 16 == 0
                and time.monotonic() - last_checkpoint >= checkpoint_seconds
            ):
                state.save(state_path)
                since_checkpoint = 0
                last_checkpoint = time.monotonic()
                report(length, state.skip, length_total)

        state.complete = True
        state.next_length = state.max_length + 1
        state.skip = 0
        state.save(state_path)
        return None
    except BaseException:
        stop.value = -2
        raise
    finally:
        if not state.complete:
            stop.value = -2
            state.save(state_path)
        for job in jobs:
            job.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
