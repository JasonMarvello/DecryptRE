"""Offline English trigram model loaded from the bundled data file.

Trigrams (three-letter sequences) are much better than single letters at
telling real words from key-guess noise. The table is derived from a
public-domain book; see ``decryptre/data/SOURCE.md``.

It is read once, on first use, and kept in memory as log-probabilities so
scoring is a plain dictionary lookup.
"""

import math
from pathlib import Path
from typing import Dict, Optional, Tuple

_LOG_TABLE: Optional[Dict[str, float]] = None
_FLOOR_LOG = math.log(1e-7)


def log_table() -> Tuple[Dict[str, float], float]:
    """Return ``(trigram -> log probability, unseen floor)``."""
    global _LOG_TABLE, _FLOOR_LOG
    if _LOG_TABLE is not None:
        return _LOG_TABLE, _FLOOR_LOG

    path = Path(__file__).with_name("data") / "trigrams.txt"
    counts: Dict[str, int] = {}
    total = 0
    try:
        lines = path.read_text(encoding="ascii", errors="ignore").splitlines()
    except OSError:
        lines = []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2 or len(parts[0]) != 3:
            continue
        try:
            count = int(parts[1])
        except ValueError:
            continue
        counts[parts[0]] = count
        total += count

    if total:
        _LOG_TABLE = {tri: math.log(count / total) for tri, count in counts.items()}
        # Unseen trigrams get a small but finite probability.
        _FLOOR_LOG = math.log(0.01 / total)
    else:
        _LOG_TABLE = {}
        _FLOOR_LOG = math.log(1e-7)
    return _LOG_TABLE, _FLOOR_LOG


def known_trigram_count() -> int:
    """How many trigrams the bundled table contains (0 if missing)."""
    return len(log_table()[0])


def trigram_logprob(a: str, b: str, c: str) -> float:
    table, floor = log_table()
    return table.get(a + b + c, floor)


def trigram_score(text: str) -> float:
    """Average log-probability per trigram (higher = more English-like)."""
    letters = [ch for ch in text.lower() if "a" <= ch <= "z"]
    if len(letters) < 3:
        return -20.0
    table, floor = log_table()
    total = 0.0
    for index in range(len(letters) - 2):
        total += table.get(
            letters[index] + letters[index + 1] + letters[index + 2], floor
        )
    return total / (len(letters) - 2)
