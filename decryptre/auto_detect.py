"""Layered auto-detection ("no passphrase" mode).

Strategy: peel one layer at a time. At each depth every plausible decoder is
tried (encodings, classical ciphers, XOR, and -- for DecryptRE containers --
a passphrase dictionary). Results are scored with :mod:`decryptre.scorer`,
the best few are kept as the next frontier, and a visited set stops cycles.

Budgets (``max_depth``, ``max_candidates``) keep the search bounded. This is
a heuristic search, not an exhaustive keyspace scan.
"""

import base64
from typing import Dict, Iterable, List, Optional

from . import classical, encodings, modern_crypto, xor
from .containers import is_container
from .models import Candidate
from .scorer import printable_ratio, score_text

XOR_PREFIX = "decryptre:xor:"


def _unique_best(candidates: Iterable[Candidate]) -> List[Candidate]:
    best: Dict[str, Candidate] = {}
    for candidate in candidates:
        current = best.get(candidate.text)
        if current is None or candidate.score > current.score:
            best[candidate.text] = candidate
    return list(best.values())


def _decode_xor_wrapper(text: str) -> Optional[Candidate]:
    if not text.strip().startswith(XOR_PREFIX):
        return None
    token = text.strip()[len(XOR_PREFIX):]
    token += "=" * ((-len(token)) % 4)
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None
    # Keep the raw bytes as latin-1 text so the XOR breaker can attack them.
    ciphertext = raw.decode("latin-1")
    return Candidate(
        ciphertext, "xor", {"op": "base64-unwrap"}, score_text(ciphertext)
    )


def _expand(
    parent: Candidate,
    wordlist: Iterable[str],
    include_substitution: bool,
) -> List[Candidate]:
    """Produce every one-layer child of ``parent``."""
    text = parent.text
    depth = parent.depth + 1
    sample = text[:4000]
    children: List[Candidate] = []

    def add(child: Candidate) -> None:
        child.depth = depth
        child.parent = f"{parent.method} {parent.describe_params()}".strip()
        if child.text and child.text != text:
            children.append(child)

    # 1. XOR wrapper produced by `decryptre encrypt --method xor`.
    wrapped = _decode_xor_wrapper(text)
    if wrapped is not None:
        add(wrapped)

    # 2. Encodings (one level).
    for name in encodings.ENCODINGS:
        if not encodings.looks_like(text, name):
            continue
        try:
            decoded = encodings.decode(text, name)
        except encodings.DecodeError:
            continue
        add(Candidate(decoded, name, {"op": "decode"}, score_text(decoded)))

    # 3. Classical ciphers.
    if any(ch.isalpha() for ch in sample):
        add_many = children.extend
        add_many(
            _with_depth(classical.break_caesar(sample, top=3), depth, parent)
        )
        add_many(_with_depth(classical.break_atbash(sample), depth, parent))
        # Vigenere and substitution are comparatively slow; they are most
        # useful on the first text layer, so only run them there.
        if depth == 1 and 20 <= len(sample) <= 1000:
            add_many(
                _with_depth(classical.break_vigenere(sample, top=2), depth, parent)
            )
        if 10 <= len(sample) <= 4000:
            add_many(
                _with_depth(classical.break_railfence(sample, top=2), depth, parent)
            )
        # Substitution is the slowest solver, so only attempt it when the
        # cheaper ciphers failed to produce readable English.
        best_so_far = max((c.score for c in children), default=float("-inf"))
        if (
            include_substitution
            and depth == 1
            and 40 <= len(sample) <= 800
            and best_so_far < -7.0
        ):
            add_many(
                _with_depth(
                    classical.break_substitution(
                        sample, restarts=3, iterations=8000, top=1
                    ),
                    depth,
                    parent,
                )
            )

    # 4. XOR. Always try it on a freshly decoded encoding layer: XOR after
    # Base64/hex is a classic combination. On the original input only try it
    # when the text does not already look like English.
    data = xor.to_bytes(sample)
    decoded_layer = parent.method in encodings.ENCODINGS
    worth_trying = (
        printable_ratio(sample) < 0.75
        or decoded_layer
        or (depth == 1 and score_text(sample) < -8.0)
    )
    if data and worth_trying:
        add_many = children.extend
        add_many(_with_depth(xor.break_single_byte(data, top=2), depth, parent))
        if 8 <= len(data) <= 4000:
            add_many(
                _with_depth(
                    xor.break_repeating_key(data, top=2), depth, parent
                )
            )

    # 5. Modern crypto: dictionary attack on DecryptRE containers only.
    if wordlist and is_container(text):
        add_many = children.extend
        add_many(
            _with_depth(
                modern_crypto.dictionary_attack(text, wordlist, top=2),
                depth,
                parent,
            )
        )

    return _unique_best(children)


def _with_depth(
    candidates: Iterable[Candidate], depth: int, parent: Candidate
) -> List[Candidate]:
    out = []
    for candidate in candidates:
        if candidate.text == parent.text:
            continue
        candidate.depth = depth
        candidate.parent = f"{parent.method} {parent.describe_params()}".strip()
        out.append(candidate)
    return out


def _select_frontier(children: List[Candidate], beam: int) -> List[Candidate]:
    """Keep the best children, plus decodes that deserve another layer.

    Encoding decodes are deterministic and cheap, so they are always carried
    forward even when the decoded text does not look like English yet (it may
    be the ciphertext of the next layer).
    """
    unique = _unique_best(children)
    unique.sort(key=lambda c: c.score, reverse=True)
    selected = unique[:beam]
    carriers = [
        c for c in unique
        if c.method in encodings.ENCODINGS or c.params.get("op") == "base64-unwrap"
    ]
    for carrier in carriers[:3]:
        if carrier not in selected:
            selected.append(carrier)
    return selected


def detect(
    text: str,
    max_depth: int = 3,
    max_candidates: int = 2000,
    top: int = 5,
    wordlist: Optional[Iterable[str]] = None,
    beam: int = 6,
    include_substitution: bool = True,
) -> List[Candidate]:
    """Return the most English-looking decryptions found, best first."""
    if max_depth < 1:
        return [Candidate(text, "input", {}, score_text(text), 0)]

    wordlist = list(wordlist or [])
    best: Dict[str, Candidate] = {}

    def remember(candidate: Candidate) -> None:
        current = best.get(candidate.text)
        if current is None or candidate.score > current.score:
            best[candidate.text] = candidate

    start = Candidate(text, "input", {}, score_text(text), 0)
    remember(start)

    frontier = [start]
    visited = set()
    produced = 0

    for _depth in range(max_depth):
        children: List[Candidate] = []
        for parent in frontier:
            if produced >= max_candidates:
                break
            for child in _expand(parent, wordlist, include_substitution):
                signature = child.signature()
                if signature in visited:
                    continue
                visited.add(signature)
                produced += 1
                remember(child)
                children.append(child)
                if produced >= max_candidates:
                    break
        if not children:
            break
        frontier = _select_frontier(children, beam)

    ranked = sorted(best.values(), key=lambda c: c.score, reverse=True)
    return ranked[:max(1, top)]
