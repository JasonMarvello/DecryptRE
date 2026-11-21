"""Layered auto-detection ("no passphrase" mode).

Strategy: peel one layer at a time. At each depth every plausible decoder is
tried (encodings, classical ciphers, XOR, and -- when a passphrase is known --
modern decryption). Results are scored with :mod:`decryptre.scorer`, the best
few are kept as the next frontier, and a visited set stops cycles.

Budgets (``max_depth``, ``max_candidates``) keep the search bounded. This is
a heuristic search, not an exhaustive keyspace scan.

Two rules keep the ranking honest:

* A candidate whose key was *verified* by the cipher (an AEAD tag checked out)
  always outranks a heuristic guess, whatever the English score says.
* Low-printability children are carried to the next depth even when they score
  badly: binary output is often the input of the next layer, not an answer.
"""

import base64
from typing import Dict, Iterable, List, Optional

from . import classical, encodings, modern_crypto, openssl_compat, xor
from .containers import is_container
from .models import Candidate
from .present import display_name
from .scorer import printable_ratio, score_text

XOR_PREFIX = "decryptre:xor:"


def _unique_best(candidates: Iterable[Candidate]) -> List[Candidate]:
    best: Dict[str, Candidate] = {}
    for candidate in candidates:
        current = best.get(candidate.text)
        if (
            current is None
            or (candidate.verified and not current.verified)
            or (
                candidate.verified == current.verified
                and candidate.score > current.score
            )
        ):
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


def _xor_key_bytes(params: Dict) -> Optional[bytes]:
    key = params.get("key")
    if isinstance(key, int):
        return bytes([key & 0xFF])
    if isinstance(key, str) and key:
        try:
            return bytes.fromhex(key)
        except ValueError:
            return None
    return None


def _rebuild_full(candidate: Candidate, text: str) -> Candidate:
    """Re-apply a recovered parameter to the whole text.

    Breaking is done on a sample for speed, but the user asked for the whole
    message: rebuilding here avoids silently truncating long plaintext.
    """
    method, params = candidate.method, candidate.params
    try:
        if method == "caesar" and "shift" in params:
            plain = classical.caesar_decrypt(text, params["shift"])
        elif method == "atbash":
            plain = classical.atbash(text)
        elif method == "vigenere" and "key" in params:
            plain = classical.vigenere_decrypt(text, params["key"])
        elif method == "railfence" and "rails" in params:
            plain = classical.railfence_decrypt(text, params["rails"])
        elif method == "substitution" and "key" in params:
            plain = classical.substitution_decrypt(text, params["key"])
        elif method == "xor":
            key = _xor_key_bytes(params)
            if not key:
                return candidate
            plain = xor.from_bytes(xor.xor_bytes(xor.to_bytes(text), key))
        else:
            return candidate
    except (ValueError, KeyError, TypeError):
        return candidate
    candidate.text = plain
    candidate.score = score_text(plain)
    return candidate


def _rank_key(candidate: Candidate):
    """Verified results first, then English-likeness."""
    return (candidate.verified, candidate.score)


def _encoding_guarantees(ranked: List[Candidate]) -> List[Candidate]:
    """Readable encoding decodes that must stay visible.

    A decode is an unambiguous transformation. On very short input a deep
    XOR-then-Caesar guess can score higher than the real decode, so one
    candidate per encoding is reserved in the visible list.
    """
    seen = set()
    out: List[Candidate] = []
    for candidate in ranked:
        if (
            candidate.method in encodings.ENCODINGS
            and candidate.depth > 0
            and candidate.text
            and printable_ratio(candidate.text) >= 0.9
            and candidate.method not in seen
        ):
            seen.add(candidate.method)
            out.append(candidate)
    return out


def _provenance(child: Candidate, depth: int, parent: Candidate) -> None:
    child.depth = depth
    child.parent = f"{parent.method} {parent.describe_params()}".strip()
    label = display_name(child.method, child.params)
    child.chain = f"{parent.chain} -> {label}" if parent.chain else label


def _expand(
    parent: Candidate,
    wordlist: Iterable[str],
    include_substitution: bool,
    passphrase: Optional[str] = None,
    openssl_progress=None,
) -> List[Candidate]:
    """Produce every one-layer child of ``parent``."""
    text = parent.text
    depth = parent.depth + 1
    sample = text[:4000]
    children: List[Candidate] = []

    def add(child: Candidate) -> None:
        _provenance(child, depth, parent)
        # An empty plaintext is legitimate when the cipher verified it.
        if (child.text or child.verified) and child.text != text:
            children.append(child)

    # 0. A known passphrase. Tried on the raw input, and on any layer that
    #    turns out to be a container, so a wrapped container still opens.
    if passphrase and (parent.depth == 0 or is_container(text)):
        hit = modern_crypto.try_decrypt_any(text, passphrase)
        if hit is not None:
            plain, alg = hit
            add(
                Candidate(
                    plain,
                    "modern",
                    {"alg": alg, "passphrase": passphrase},
                    score_text(plain),
                    verified=True,
                )
            )

    # 0b. OpenSSL `enc` output ("Salted__"). Same idea, different format.
    #     Checked on every layer: a blob is sometimes wrapped in base64 first.
    if passphrase and openssl_compat.looks_like(text):
        hit = openssl_compat.try_decrypt(text, passphrase)
        if hit is not None:
            plain, alg = hit
            add(
                Candidate(
                    plain,
                    "openssl",
                    {"alg": alg, "passphrase": passphrase},
                    score_text(plain),
                    verified=True,
                )
            )

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
        children.extend(
            _with_depth(classical.break_caesar(sample, top=3), depth, parent)
        )
        children.extend(_with_depth(classical.break_atbash(sample), depth, parent))
        # Vigenere and substitution are comparatively slow. They run on the
        # first text layer, and directly after an encoding decode, which is
        # how stacked puzzles (Base64 then Vigenere) are put together.
        text_layer = depth == 1 or parent.method in encodings.ENCODINGS
        if text_layer and 20 <= len(sample) <= 2000:
            children.extend(
                _with_depth(classical.break_vigenere(sample, top=2), depth, parent)
            )
        if 10 <= len(sample) <= 4000:
            children.extend(
                _with_depth(classical.break_railfence(sample, top=2), depth, parent)
            )
        # Substitution is the slowest solver, so only attempt it when the
        # cheaper ciphers failed to produce readable English.
        best_so_far = max((c.score for c in children), default=float("-inf"))
        # The solver needs a few hundred letters to be trustworthy. Running
        # it on a short greeting produced confident-looking nonsense that
        # outranked the exact Caesar answer, so require a real paragraph.
        if (
            include_substitution
            and text_layer
            and 120 <= len(sample) <= 2000
            and best_so_far < -7.0
        ):
            children.extend(
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
        children.extend(_with_depth(xor.break_single_byte(data, top=2), depth, parent))
        if 8 <= len(data) <= 4000:
            children.extend(
                _with_depth(xor.break_repeating_key(data, top=2), depth, parent)
            )

    # 5. Modern crypto without a known passphrase: dictionary attack on
    #    DecryptRE containers only.
    if wordlist and is_container(text):
        children.extend(
            _with_depth(
                modern_crypto.dictionary_attack(text, wordlist, top=2), depth, parent
            )
        )
    if wordlist and openssl_compat.looks_like(text):
        children.extend(
            _with_depth(
                openssl_compat.dictionary_attack(
                    text, wordlist, top=2, progress=openssl_progress
                ),
                depth,
                parent,
            )
        )

    # Rebuild sampled results against the full text so nothing is truncated.
    if len(text) > 4000 or (
        len(text) > 2000 and any(c.method == "substitution" for c in children)
    ):
        children = [_rebuild_full(child, text) for child in children]

    return _unique_best(children)


def _with_depth(
    candidates: Iterable[Candidate], depth: int, parent: Candidate
) -> List[Candidate]:
    out = []
    for candidate in candidates:
        if candidate.text == parent.text:
            continue
        _provenance(candidate, depth, parent)
        out.append(candidate)
    return out


def _select_frontier(children: List[Candidate], beam: int) -> List[Candidate]:
    """Keep the best children, plus decodes that deserve another layer.

    Encoding decodes are deterministic and cheap, so they are always carried
    forward even when the decoded text does not look like English yet (it may
    be the ciphertext of the next layer). Binary output and verified results
    are carried too: the next layer may be hidden behind them.
    """
    unique = _unique_best(children)
    unique.sort(key=_rank_key, reverse=True)
    selected = unique[:beam]
    carriers = [
        c
        for c in unique
        if c.method in encodings.ENCODINGS
        or c.params.get("op") == "base64-unwrap"
        or c.verified
        or printable_ratio(c.text) < 0.75
    ]

    def carrier_priority(candidate: Candidate):
        if candidate.verified:
            return 0
        if candidate.params.get("op") == "base64-unwrap":
            return 1
        if candidate.method in encodings.ENCODINGS:
            return 2
        return 3

    # Score alone must not decide here: a low-scoring XOR unwrap is the only
    # key to the next layer, while binary Base64 decodes score higher and are
    # usually dead ends. Verified results always travel.
    carriers.sort(key=lambda c: (carrier_priority(c), -c.score))
    for carrier in carriers[:4]:
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
    passphrase: Optional[str] = None,
    openssl_progress=None,
) -> List[Candidate]:
    """Return the best decryptions found, verified results first."""
    if max_depth < 1:
        return [Candidate(text, "input", {}, score_text(text), 0)]

    wordlist = list(wordlist or [])
    best: Dict[str, Candidate] = {}

    def remember(candidate: Candidate) -> None:
        current = best.get(candidate.text)
        if (
            current is None
            or (candidate.verified and not current.verified)
            or (
                candidate.verified == current.verified
                and candidate.score > current.score
            )
        ):
            best[candidate.text] = candidate

    start = Candidate(text, "input", {}, score_text(text), 0)
    remember(start)

    frontier = [start]
    visited = set()

    for _depth in range(max_depth):
        children: List[Candidate] = []
        for parent in frontier:
            if len(children) >= max_candidates:
                break
            for child in _expand(
                parent,
                wordlist,
                include_substitution,
                passphrase,
                openssl_progress,
            ):
                signature = child.signature()
                if signature in visited:
                    continue
                visited.add(signature)
                remember(child)
                children.append(child)
                if len(children) >= max_candidates:
                    break
        if not children:
            break
        frontier = _select_frontier(children, beam)

    ranked = sorted(best.values(), key=_rank_key, reverse=True)
    limit = max(1, top)
    selected = ranked[:limit]
    for candidate in _encoding_guarantees(ranked)[:limit]:
        if candidate in selected:
            continue
        if len(selected) < limit:
            selected.append(candidate)
        else:
            for index in range(len(selected) - 1, -1, -1):
                if not selected[index].verified:
                    selected[index] = candidate
                    break
    selected.sort(key=_rank_key, reverse=True)
    return selected
