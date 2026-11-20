"""Offline English-likelihood scoring.

The scorer answers one question: "how much does this look like English?"
It uses three cheap, fully offline signals:

1. How printable the text is (binary garbage loses immediately).
2. Letter frequency, compared with normal English via chi-squared.
3. Common English bigrams and a short list of common words.

All methods share this one scale, so candidates from different decryptors
can be ranked against each other. Higher scores are better; values are
roughly between -15 (gibberish) and -3 (clear English).
"""

import math
from collections import Counter
from typing import Dict

from .ngrams import trigram_score

ENGLISH_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702,
    "f": 2.228, "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153,
    "k": 0.772, "l": 4.025, "m": 2.406, "n": 6.749, "o": 7.507,
    "p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056,
    "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150, "y": 1.974,
    "z": 0.074,
}

# Common English bigrams, most frequent first. Approximate relative counts;
# they only need to rank text, not reproduce a research corpus.
_COMMON_BIGRAMS = (
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt "
    "ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be "
    "ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly "
    "nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni "
    "ts mo ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld "
    "ry mp fe bl ab gh ty op wo sa ax ki bu od fr if tt au ay eu qu"
).split()

_BIGRAM_TOTAL = 0.0
_BIGRAM_PROB: Dict[str, float] = {}
for _rank, _bg in enumerate(_COMMON_BIGRAMS):
    _BIGRAM_TOTAL += 10000 * (0.96 ** _rank)
for _rank, _bg in enumerate(_COMMON_BIGRAMS):
    _BIGRAM_PROB[_bg] = (10000 * (0.96 ** _rank)) / _BIGRAM_TOTAL

_UNKNOWN_BIGRAM = 1e-5

COMMON_WORDS = {
    "the", "of", "and", "to", "a", "in", "is", "it", "you", "that", "he",
    "was", "for", "on", "are", "as", "with", "his", "they", "at", "be",
    "this", "have", "from", "or", "one", "had", "by", "not", "but", "what",
    "all", "were", "we", "when", "your", "can", "said", "there", "use",
    "an", "each", "which", "she", "do", "how", "their", "if", "will", "up",
    "other", "about", "out", "many", "then", "them", "these", "so", "some",
    "her", "would", "make", "like", "him", "into", "time", "has", "look",
    "two", "more", "write", "go", "see", "number", "no", "way", "could",
    "people", "my", "than", "first", "water", "been", "call", "who", "its",
    "now", "find", "long", "down", "day", "did", "get", "come", "made",
    "may", "part", "flag", "secret", "message", "key", "hello", "world",
    "please", "thanks", "password", "text", "test", "the", "and",
}


def printable_ratio(text: str) -> float:
    """Fraction of characters that are normal printable text."""
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch in "\n\r\t" or 32 <= ord(ch) <= 126)
    return printable / len(text)


def chi_square(text: str) -> float:
    """Chi-squared distance from English letter frequencies (lower = better)."""
    letters = [ch for ch in text.lower() if "a" <= ch <= "z"]
    if not letters:
        return float("inf")
    counts = Counter(letters)
    total = len(letters)
    score = 0.0
    for letter, pct in ENGLISH_FREQ.items():
        expected = total * pct / 100.0
        observed = counts.get(letter, 0)
        score += (observed - expected) ** 2 / expected
    return score / total


def bigram_score(text: str) -> float:
    """Average log-probability of the letter bigrams (higher = better)."""
    letters = [ch for ch in text.lower() if "a" <= ch <= "z"]
    if len(letters) < 2:
        return -12.0
    total = 0.0
    for i in range(len(letters) - 1):
        pair = letters[i] + letters[i + 1]
        total += math.log(_BIGRAM_PROB.get(pair, _UNKNOWN_BIGRAM))
    return total / (len(letters) - 1)


def common_word_ratio(text: str) -> float:
    words = [w.strip(".,;:!?\"'()[]{}<>") for w in text.lower().split()]
    words = [w for w in words if w]
    if not words:
        return 0.0
    return sum(1 for w in words if w in COMMON_WORDS) / len(words)


def vowel_word_ratio(text: str) -> float:
    """Fraction of alphabetic words that contain no vowel (gibberish signal)."""
    words = [
        "".join(ch for ch in word.lower() if "a" <= ch <= "z")
        for word in text.split()
    ]
    words = [word for word in words if word]
    if not words:
        return 0.0
    no_vowel = sum(1 for word in words if not any(v in word for v in "aeiouy"))
    return no_vowel / len(words)


def score_text(text: str) -> float:
    """Score how English-like ``text`` is. Higher is better."""
    if not text:
        return -1000.0
    ratio = printable_ratio(text)
    if ratio < 0.90:
        # Almost certainly not readable text; keep the ordering monotonic.
        return -500.0 - 100.0 * (1.0 - ratio)

    letters = sum(1 for ch in text.lower() if "a" <= ch <= "z")
    if letters < 4:
        return -200.0

    chi = chi_square(text)
    if chi == float("inf"):
        return -200.0
    # Chi-squared is noisy on short samples, so trust it more as text grows.
    # English prose is ~0.1-0.4 once there is enough text; random letters 1.0+.
    chi_weight = min(1.0, letters / 150.0)
    frequency_part = -2.0 * min(chi, 5.0) * chi_weight

    # Trigrams carry most of the signal: real words use common sequences.
    trigram_part = trigram_score(text)

    spaces = text.count(" ") / len(text)
    space_part = -20.0 * abs(spaces - 0.15)

    word_part = 3.0 * common_word_ratio(text)

    # Garbage from wrong keys often mixes cases or digits in odd places.
    alpha = [ch for ch in text if ch.isalpha()]
    upper_ratio = (sum(1 for ch in alpha if ch.isupper()) / len(alpha)) if alpha else 0.0
    case_part = -1.5 * max(0.0, upper_ratio - 0.5)
    digits = sum(1 for ch in text if ch.isdigit()) / len(text)
    digit_part = -3.0 * min(digits, 0.3)

    vowel_part = -4.0 * vowel_word_ratio(text)

    return (
        frequency_part + trigram_part + space_part + word_part
        + case_part + digit_part + vowel_part
    )


def rank(texts):
    """Return ``(score, text)`` pairs sorted best-first."""
    return sorted(((score_text(t), t) for t in texts), reverse=True)
