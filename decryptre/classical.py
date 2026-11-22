"""Classical ciphers: Caesar/ROT-N, Atbash, Vigenere, Rail Fence, substitution.

Every "break_*" function is offline parameter search guided by
:func:`decryptre.scorer.score_text`; nothing here needs a network connection.
Substitution solving is a best-effort hill climb and can fail on short or
unusual text -- the README says so too.
"""

import math
import random
from collections import Counter
from typing import List

from .models import Candidate
from .ngrams import log_table
from .scorer import ENGLISH_FREQ, chi_square, score_text

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
_ALPHA_INDEX = {c: i for i, c in enumerate(ALPHABET)}


# ---------------------------------------------------------------------------
# Caesar / ROT-N
# ---------------------------------------------------------------------------

def caesar_encrypt(text: str, shift: int) -> str:
    shift %= 26
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


def rot13(text: str) -> str:
    return caesar_encrypt(text, 13)


def break_caesar(text: str, top: int = 5) -> List[Candidate]:
    results = []
    for shift in range(26):
        plain = caesar_decrypt(text, shift)
        results.append(
            Candidate(plain, "caesar", {"shift": shift}, score_text(plain))
        )
    results.sort(key=lambda c: c.score, reverse=True)
    return results[:top]


# ---------------------------------------------------------------------------
# Atbash
# ---------------------------------------------------------------------------

def atbash(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(122 - (ord(ch) - 97)))
        elif "A" <= ch <= "Z":
            out.append(chr(90 - (ord(ch) - 65)))
        else:
            out.append(ch)
    return "".join(out)


def break_atbash(text: str) -> List[Candidate]:
    plain = atbash(text)
    return [Candidate(plain, "atbash", {}, score_text(plain))]


# ---------------------------------------------------------------------------
# Vigenere
# ---------------------------------------------------------------------------

def _vigenere_shift(text: str, key: str, direction: int) -> str:
    key_letters = [c for c in key.lower() if c in _ALPHA_INDEX]
    if not key_letters:
        raise ValueError("Vigenere key must contain at least one letter")
    out = []
    key_pos = 0
    for ch in text:
        if "a" <= ch <= "z" or "A" <= ch <= "Z":
            base = 97 if ch.islower() else 65
            shift = _ALPHA_INDEX[key_letters[key_pos % len(key_letters)]]
            out.append(chr((ord(ch) - base + direction * shift) % 26 + base))
            key_pos += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_encrypt(text: str, key: str) -> str:
    return _vigenere_shift(text, key, 1)


def vigenere_decrypt(text: str, key: str) -> str:
    return _vigenere_shift(text, key, -1)


def _best_shift_for_column(letters: str) -> int:
    """Pick the Caesar shift whose output best matches English frequencies."""
    best_shift, best_score = 0, float("inf")
    for shift in range(26):
        shifted = "".join(
            chr((ord(c) - 97 - shift) % 26 + 97) for c in letters
        )
        value = chi_square(shifted)
        if value < best_score:
            best_shift, best_score = shift, value
    return best_shift


def _average_ic(letters: str, key_length: int) -> float:
    total = 0.0
    for column in range(key_length):
        counts = Counter(letters[column::key_length])
        n = sum(counts.values())
        if n < 2:
            continue
        total += sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))
    return total / key_length


def _refine_key(key: str, sample: str, passes: int = 2) -> str:
    """Hill-climb the key one letter at a time against the English score."""
    best = list(key)
    best_score = score_text(vigenere_decrypt(sample, key))
    for _ in range(passes):
        improved = False
        for index in range(len(best)):
            original = best[index]
            best_letter, best_value = original, best_score
            for letter in ALPHABET:
                if letter == original:
                    continue
                trial = list(best)
                trial[index] = letter
                value = score_text(vigenere_decrypt(sample, "".join(trial)))
                if value > best_value:
                    best_letter, best_value = letter, value
            if best_letter != original:
                best[index] = best_letter
                best_score = best_value
                improved = True
        if not improved:
            break
    return "".join(best)


def break_vigenere(text: str, max_key_length: int = 12, top: int = 5) -> List[Candidate]:
    letters_only = "".join(c for c in text.lower() if c in _ALPHA_INDEX)
    if len(letters_only) < 8:
        return []
    max_key_length = min(max_key_length, max(1, len(letters_only) // 4))

    # Prefer lengths whose columns look like English (index of coincidence).
    lengths = sorted(
        range(1, max_key_length + 1),
        key=lambda length: abs(_average_ic(letters_only, length) - 0.066),
    )[:4]
    if 1 not in lengths:
        lengths.append(1)

    sample = text[:500]
    results: List[Candidate] = []
    for length in lengths:
        key_chars = []
        for column in range(length):
            column_letters = letters_only[column::length]
            if not column_letters:
                key_chars.append("a")
                continue
            key_chars.append(ALPHABET[_best_shift_for_column(column_letters)])
        key = _refine_key("".join(key_chars), sample)
        plain = vigenere_decrypt(text, key)
        results.append(
            Candidate(plain, "vigenere", {"key": key}, score_text(plain))
        )
    results.sort(key=lambda c: c.score, reverse=True)
    return results[:top]


# ---------------------------------------------------------------------------
# Rail fence
# ---------------------------------------------------------------------------

def _rail_pattern(length: int, rails: int) -> List[int]:
    if rails <= 1:
        return [0] * length
    pattern = []
    rail = 0
    direction = 1
    for _ in range(length):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return pattern


def railfence_encrypt(text: str, rails: int) -> str:
    if rails <= 1:
        return text
    rows = [[] for _ in range(rails)]
    for ch, rail in zip(text, _rail_pattern(len(text), rails)):
        rows[rail].append(ch)
    return "".join("".join(row) for row in rows)


def railfence_decrypt(text: str, rails: int) -> str:
    if rails <= 1:
        return text
    pattern = _rail_pattern(len(text), rails)
    counts = Counter(pattern)
    rows: List[List[str]] = []
    index = 0
    for rail in range(rails):
        size = counts[rail]
        rows.append(list(text[index:index + size]))
        index += size
    pointers = [0] * rails
    out = []
    for rail in pattern:
        out.append(rows[rail][pointers[rail]])
        pointers[rail] += 1
    return "".join(out)


def break_railfence(text: str, max_rails: int = 12, top: int = 5) -> List[Candidate]:
    results = []
    for rails in range(2, max_rails + 1):
        if rails >= len(text):
            break
        plain = railfence_decrypt(text, rails)
        results.append(
            Candidate(plain, "railfence", {"rails": rails}, score_text(plain))
        )
    results.sort(key=lambda c: c.score, reverse=True)
    return results[:top]


# ---------------------------------------------------------------------------
# Simple substitution (best-effort hill climb)
# ---------------------------------------------------------------------------

def substitution_decrypt(text: str, mapping) -> str:
    """Decrypt with a cipher-letter -> plain-letter mapping.

    ``mapping`` may be a 26-character string where position *i* is the plain
    letter for ciphertext letter ``ALPHABET[i]``, or a dict.
    """
    if isinstance(mapping, str):
        if len(mapping) != 26:
            raise ValueError("substitution key must be 26 letters")
        table: Dict[str, str] = {ALPHABET[i]: mapping[i].lower() for i in range(26)}
    else:
        table = {str(k).lower(): str(v).lower() for k, v in mapping.items()}
    out = []
    for ch in text:
        low = ch.lower()
        if low in table:
            plain = table[low]
            out.append(plain.upper() if ch.isupper() else plain)
        else:
            out.append(ch)
    return "".join(out)


def substitution_encrypt(text: str, mapping) -> str:
    """Encrypt with a cipher-letter -> plain-letter mapping (inverse of decrypt)."""
    if isinstance(mapping, str):
        if len(mapping) != 26:
            raise ValueError("substitution key must be 26 letters")
        table = {ALPHABET[i]: mapping[i].lower() for i in range(26)}
    else:
        table = {str(k).lower(): str(v).lower() for k, v in mapping.items()}
    inverse = {plain: cipher for cipher, plain in table.items()}
    out = []
    for ch in text:
        low = ch.lower()
        if low in inverse:
            cipher = inverse[low]
            out.append(cipher.upper() if ch.isupper() else cipher)
        else:
            out.append(ch)
    return "".join(out)


_TRIGRAM_SCALE = 26 * 26


def _trigram_score_table(table, floor):
    """Lookup table indexed by three plaintext-letter positions (0-25)."""
    scores = [floor] * (26 * 26 * 26)
    index = _ALPHA_INDEX
    for trigram, value in table.items():
        if len(trigram) == 3:
            scores[
                index[trigram[0]] * _TRIGRAM_SCALE
                + index[trigram[1]] * 26
                + index[trigram[2]]
            ] = value
    return scores


def _trigram_score(key, rows, scores) -> float:
    """Score integer-keyed trigram rows against a precomputed table."""
    total = 0.0
    for a, b, c, count in rows:
        total += count * scores[
            key[a] * _TRIGRAM_SCALE + key[b] * 26 + key[c]
        ]
    return total


def _affected_trigrams(trigrams, first: int, second: int):
    """Indexes of trigrams whose score can change in a two-letter swap."""
    return tuple(
        position
        for position, (a, b, c, _count) in enumerate(trigrams)
        if first in (a, b, c) or second in (a, b, c)
    )


def _anneal(key, trigrams, rng, iterations: int, scores, affected_cache):
    """Simulated-annealing swap search over the 26-letter key."""
    current = _trigram_score(key, trigrams, scores)
    best_score, best_key = current, list(key)
    trigram_scores = [
        count * scores[key[a] * _TRIGRAM_SCALE + key[b] * 26 + key[c]]
        for a, b, c, count in trigrams
    ]

    for step in range(iterations):
        i, j = rng.randrange(26), rng.randrange(26)
        if i == j:
            continue
        pair = (i, j) if i < j else (j, i)
        affected = affected_cache.get(pair)
        if affected is None:
            affected = _affected_trigrams(trigrams, i, j)
            affected_cache[pair] = affected

        old_scores = [trigram_scores[index] for index in affected]
        before = sum(old_scores)
        key[i], key[j] = key[j], key[i]
        after = 0.0
        for position in affected:
            a, b, c, count = trigrams[position]
            value = count * scores[
                key[a] * _TRIGRAM_SCALE + key[b] * 26 + key[c]
            ]
            trigram_scores[position] = value
            after += value

        accept = after >= before
        if not accept:
            temperature = max(0.02, 0.5 * (1.0 - step / max(1, iterations)))
            accept = rng.random() < math.exp((after - before) / max(1e-9, temperature * 4))
        if accept:
            current += after - before
            if current > best_score:
                best_score, best_key = current, list(key)
        else:
            key[i], key[j] = key[j], key[i]
            for position, value in zip(affected, old_scores):
                trigram_scores[position] = value

    return best_key


def break_substitution(
    text: str,
    restarts: int = 5,
    iterations: int = 10000,
    seed: int = 0,
    top: int = 3,
) -> List[Candidate]:
    """Best-effort substitution solver using an English trigram model.

    Substitution needs a fair amount of text to solve reliably (a couple of
    hundred letters is comfortable; a short greeting is not). When it is not
    confident the candidate list shows the alternatives, so treat the result
    as a suggestion and verify it by reading.
    """
    sample = text[:2000]
    letters = [c for c in sample.lower() if c in _ALPHA_INDEX]
    if len(letters) < 30:
        return []

    index = _ALPHA_INDEX
    trigrams = [
        (index[a], index[b], index[c], count)
        for (a, b, c), count in Counter(
            zip(letters, letters[1:], letters[2:])
        ).items()
    ]
    table, floor = log_table()
    scores = _trigram_score_table(table, floor)

    frequencies = Counter(letters)
    by_cipher_frequency = sorted(ALPHABET, key=lambda c: (-frequencies[c], c))
    by_english_frequency = sorted(ALPHABET, key=lambda c: -ENGLISH_FREQ[c])
    seed_key = [0] * 26
    for cipher_letter, plain_letter in zip(by_cipher_frequency, by_english_frequency):
        seed_key[index[cipher_letter]] = index[plain_letter]

    rng = random.Random(seed)
    affected_cache = {}
    solved = []
    for restart in range(max(1, restarts)):
        key = list(seed_key)
        # Later restarts start a few swaps away from the frequency guess.
        for _ in range(min(restart, 6)):
            a, b = rng.randrange(26), rng.randrange(26)
            key[a], key[b] = key[b], key[a]
        best_key = _anneal(
            key, trigrams, rng, iterations, scores, affected_cache
        )
        solved.append(
            (
                _trigram_score(best_key, trigrams, scores),
                "".join(ALPHABET[position] for position in best_key),
            )
        )

    results = []
    seen = set()
    for _, key in sorted(solved, reverse=True):
        if key in seen:
            continue
        seen.add(key)
        plain = substitution_decrypt(sample, key)
        results.append(
            Candidate(plain, "substitution", {"key": key}, score_text(plain))
        )
    return results[:top]


# ---------------------------------------------------------------------------
# No-passphrase entry point used by auto-detect
# ---------------------------------------------------------------------------

def break_classical(text: str, top: int = 5) -> List[Candidate]:
    """Run every classical breaker on ``text`` and return the best results."""
    results: List[Candidate] = []
    results.extend(break_caesar(text, top=top))
    results.extend(break_atbash(text))
    results.extend(break_vigenere(text, top=top))
    results.extend(break_railfence(text, top=top))
    # Substitution is the slowest, so only attempt it on text that could
    # plausibly contain enough English signal.
    if 40 <= len(text) <= 2000:
        results.extend(
            break_substitution(text, restarts=4, iterations=800, top=2)
        )
    results.sort(key=lambda c: c.score, reverse=True)
    return results[:top]
