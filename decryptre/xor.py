"""XOR encryption and offline key recovery.

XOR with a short key is a classic CTF layer. Without a passphrase DecryptRE
tries every single-byte key (0-255), and for repeating keys guesses the key
length from the index of coincidence before solving each column.
"""

from collections import Counter
from typing import List, Optional, Union

from .models import Candidate
from .scorer import chi_square, printable_ratio, score_text

# Long inputs are truncated for scoring so attacks stay fast.
SCORE_SAMPLE = 2000


def to_bytes(text: str) -> bytes:
    """Convert text back to bytes, preserving original file bytes if possible."""
    try:
        return text.encode("latin-1")
    except UnicodeEncodeError:
        return text.encode("utf-8", "surrogateescape")


def from_bytes(data: bytes) -> str:
    """Convert bytes to text without ever raising."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def xor_bytes(data: bytes, key: Union[bytes, str]) -> bytes:
    if isinstance(key, str):
        key = to_bytes(key)
    if not key:
        raise ValueError("XOR key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_encrypt(text: str, key: Union[bytes, str]) -> bytes:
    return xor_bytes(to_bytes(text), key)


def xor_decrypt(text: str, key: Union[bytes, str]) -> str:
    return from_bytes(xor_bytes(to_bytes(text), key))


def index_of_coincidence(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    counts = Counter(data)
    pairs = sum(count * (count - 1) for count in counts.values())
    return pairs / (len(data) * (len(data) - 1))


def _column_score(data: bytes) -> float:
    """Cheap per-column heuristic: printable text that looks like English."""
    if not data:
        return float("-inf")
    sample = data[:SCORE_SAMPLE]
    letters = sample.decode("latin-1")
    ratio = printable_ratio(letters)
    chi = chi_square(letters)
    if chi == float("inf"):
        return -100.0 + ratio
    return -2.0 * min(chi, 5.0) + 5.0 * ratio


def break_single_byte(data: bytes, top: int = 5) -> List[Candidate]:
    sample = data[:SCORE_SAMPLE]
    results = []
    for key in range(256):
        plain = xor_bytes(sample, bytes([key]))
        text = from_bytes(plain)
        results.append(
            Candidate(text, "xor", {"key": key, "key_length": 1}, score_text(text))
        )
    results.sort(key=lambda c: c.score, reverse=True)
    return results[:top]


def _candidate_key_lengths(data: bytes, max_key_length: int, top: int = 6) -> List[int]:
    if len(data) < 8:
        return [1]
    scored = []
    for length in range(1, min(max_key_length, len(data) // 2) + 1):
        columns = [data[i::length] for i in range(length)]
        average_ic = sum(index_of_coincidence(col) for col in columns) / length
        scored.append((abs(average_ic - 0.066), length))
    scored.sort()
    lengths = [length for _, length in scored[:top]]
    if 1 not in lengths:
        lengths.append(1)
    return lengths


def break_repeating_key(
    data: bytes, max_key_length: int = 32, top: int = 5
) -> List[Candidate]:
    sample = data[:SCORE_SAMPLE]
    results = []
    for length in _candidate_key_lengths(sample, max_key_length):
        key = bytearray()
        for column in range(length):
            column_data = sample[column::length]
            best_key, best_score = 0, float("-inf")
            for candidate in range(256):
                value = _column_score(
                    bytes(b ^ candidate for b in column_data)
                )
                if value > best_score:
                    best_key, best_score = candidate, value
            key.append(best_key)
        key_bytes = bytes(key)
        text = from_bytes(xor_bytes(sample, key_bytes))
        results.append(
            Candidate(
                text,
                "xor",
                {"key": key_bytes.hex(), "key_length": length},
                score_text(text),
            )
        )
    results.sort(key=lambda c: c.score, reverse=True)
    return results[:top]


def break_xor(data: bytes, max_key_length: int = 32, top: int = 5) -> List[Candidate]:
    """Try both single-byte and repeating-key attacks and merge the results."""
    results = break_single_byte(data, top=top)
    if len(data) >= 8:
        results.extend(break_repeating_key(data, max_key_length=max_key_length, top=top))
    results.sort(key=lambda c: c.score, reverse=True)
    # Drop duplicate plaintexts.
    seen = set()
    unique = []
    for candidate in results:
        if candidate.text in seen:
            continue
        seen.add(candidate.text)
        unique.append(candidate)
    return unique[:top]
