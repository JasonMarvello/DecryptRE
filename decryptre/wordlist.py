"""Tiered, streaming access to bundled wordlists.

Small and medium tiers ship with DecryptRE. The optional large tier adds a
locally built RockYou file and is never part of the installed package. The
5m/10m/50m/100m tiers are generated deterministically from the bundled
language lists and a small name-seed file, so they add no wordlist data to the
wheel. Candidate lines are yielded as raw bytes: passphrases are byte strings,
and decoding them as UTF-8 first would change non-ASCII entries.
"""

import gzip
import json
import zlib
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

WORDLIST_DIR = Path(__file__).parent / "wordlists"
MANIFEST_PATH = WORDLIST_DIR / "manifest.json"
ROCKYOU_META_PATH = WORDLIST_DIR / "rockyou-large.json"
NAMES_PATH = WORDLIST_DIR / "names.txt"
GENERATED_TIERS = {
    "5m": 5_000_000,
    "10m": 10_000_000,
    "50m": 50_000_000,
    "100m": 100_000_000,
}
GENERATED_SUFFIX_LIMIT = 1_000_000
TIERS = ("small", "medium", "large") + tuple(GENERATED_TIERS)
CASE_MODES = ("off", "common", "all")
LARGE_NOT_INSTALLED = (
    "the large tier is not installed. From a source checkout, run "
    "`python tools/build_wordlists.py --fetch-rockyou` to download "
    "and deduplicate RockYou locally. It is not shipped with the "
    "PyPI package."
)


class WordlistError(ValueError):
    """Raised when a tier or wordlist file cannot be used."""


def _large_artifact() -> Tuple[Dict, Path]:
    """Return validated local RockYou metadata and its artifact path."""
    try:
        meta = json.loads(ROCKYOU_META_PATH.read_text(encoding="utf-8"))
        if not isinstance(meta, dict):
            raise ValueError("metadata is not an object")
        name = str(meta["file"])
        if Path(name).is_absolute() or Path(name).name != name:
            raise ValueError("metadata path is not a bare filename")
        if int(meta["count"]) < 0:
            raise ValueError("negative candidate count")
        path = WORDLIST_DIR / name
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise WordlistError(LARGE_NOT_INSTALLED) from exc

    if not path.is_file():
        raise WordlistError(LARGE_NOT_INSTALLED)

    expected_bytes = meta.get("bytes")
    if expected_bytes is not None:
        try:
            expected = int(expected_bytes)
        except (TypeError, ValueError) as exc:
            raise WordlistError(
                "large tier metadata has an invalid byte count; rebuild it"
            ) from exc
        try:
            actual = path.stat().st_size
        except OSError as exc:
            raise WordlistError(LARGE_NOT_INSTALLED) from exc
        if actual != expected:
            raise WordlistError(
                "large tier artifact is incomplete; rebuild it with "
                "`python tools/build_wordlists.py --fetch-rockyou --force`"
            )
    return meta, path


def _manifest() -> Dict:
    try:
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise WordlistError(f"cannot read wordlist manifest: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("tiers"), dict):
        raise WordlistError("wordlist manifest is malformed")
    return payload


def tier_files(tier: str) -> List[Path]:
    """Return the ordered files for ``tier`` without opening them."""
    if tier not in TIERS:
        raise WordlistError(f"unknown wordlist tier: {tier}")
    if tier in GENERATED_TIERS:
        raise WordlistError(
            "generated tiers have no files; use iter_tier() to stream them"
        )
    manifest = _manifest()
    tiers = manifest["tiers"]
    if tier == "large":
        medium = tiers.get("medium")
        if not isinstance(medium, dict):
            raise WordlistError("wordlist manifest has no medium tier")
        _meta, local = _large_artifact()
        return [WORDLIST_DIR / name for name in medium["files"]] + [local]

    entry = tiers.get(tier)
    if not isinstance(entry, dict) or not entry.get("files"):
        raise WordlistError(f"wordlist manifest has no {tier} tier")
    return [WORDLIST_DIR / str(name) for name in entry["files"]]


def tier_count(tier: str) -> int:
    """Number of candidates in ``tier``, from the manifest/local metadata."""
    if tier not in TIERS:
        raise WordlistError(f"unknown wordlist tier: {tier}")
    manifest = _manifest()
    if tier in GENERATED_TIERS:
        try:
            medium = int(manifest["tiers"]["medium"]["count"])
        except (KeyError, TypeError, ValueError) as exc:
            raise WordlistError(
                "wordlist manifest has no count for medium"
            ) from exc
        total = GENERATED_TIERS[tier]
        if total <= medium:
            raise WordlistError(
                f"generated tier {tier} must be larger than medium"
            )
        return total
    if tier == "large":
        try:
            medium = int(manifest["tiers"]["medium"]["count"])
        except (KeyError, TypeError, ValueError) as exc:
            raise WordlistError(
                "wordlist manifest has no count for medium"
            ) from exc
        meta, _path = _large_artifact()
        return medium + int(meta["count"])
    try:
        return int(manifest["tiers"][tier]["count"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WordlistError(f"wordlist manifest has no count for {tier}") from exc


def iter_file(path: Path, *, comments: bool = True) -> Iterator[bytes]:
    """Yield non-empty lines from a plain wordlist as bytes.

    Custom lists use the documented ``#`` comment convention: only a ``#`` in
    the first column starts a comment. All other whitespace is preserved.
    Bundled tiers pass ``comments=False`` because a password such as ``#1`` is
    data, not a comment.
    """
    path = Path(path)
    if not path.is_file():
        raise WordlistError(f"wordlist not found: {path}")
    try:
        with path.open("rb") as handle:
            for line in handle:
                candidate = line.rstrip(b"\r\n")
                if not candidate:
                    continue
                if comments and candidate.startswith(b"#"):
                    continue
                yield candidate
    except OSError as exc:
        raise WordlistError(f"cannot read wordlist: {path}: {exc}") from exc


def count_file(path: Path) -> int:
    """Count usable lines in a custom wordlist without keeping them."""
    return sum(1 for _ in iter_file(path))


def _seed_key(seed: bytes) -> bytes:
    """Case-insensitive ownership key for ASCII seeds; exact for other bytes."""
    return seed.lower() if seed.isascii() else seed


def _load_seeds(
    path: Path, seen: set, *, comments: bool = False
) -> List[bytes]:
    """Load one seed file, skipping seeds already owned by another pool."""
    seeds = []
    for seed in iter_file(path, comments=comments):
        key = _seed_key(seed)
        if key in seen:
            continue
        seen.add(key)
        seeds.append(seed)
    return seeds


def _round_robin(groups: List[List[bytes]]) -> List[bytes]:
    """Interleave language pools so every language gets generated coverage."""
    combined = []
    index = 0
    while True:
        added = False
        for group in groups:
            if index < len(group):
                combined.append(group[index])
                added = True
        if not added:
            return combined
        index += 1


def _seed_forms(seed: bytes) -> List[bytes]:
    """Case variants for a seed, without changing non-ASCII bytes."""
    forms = [seed]
    if seed.isascii():
        for form in (seed.lower(), seed.title(), seed.upper()):
            if form and form not in forms:
                forms.append(form)
    return forms


def case_forms(candidate: bytes) -> List[bytes]:
    """Return the original, Capitalised and UPPERCASE forms of a candidate.

    Non-ASCII candidates are returned unchanged: changing their case would not
    reliably reproduce the bytes the user typed.
    """
    if not candidate.isascii():
        return [candidate]
    capitalised = candidate[:1].upper() + candidate[1:]
    forms = [candidate]
    for form in (capitalised, candidate.upper()):
        if form not in forms:
            forms.append(form)
    return forms


def iter_case_variants(
    candidates: Iterator[bytes], mode: str = "off", prefix: Optional[int] = None
) -> Iterator[bytes]:
    """Yield ``candidates`` with their case forms added.

    ``off`` is a pure pass-through. ``common`` expands the first ``prefix``
    candidates (the small tier) and every candidate when no prefix is given
    (a custom list). ``all`` expands every candidate. Forms are deduplicated
    per candidate only; a streamed list is never held in memory just to
    deduplicate across lines.
    """
    if mode not in CASE_MODES:
        raise WordlistError(f"unknown case variant mode: {mode}")
    if mode == "off":
        yield from candidates
        return
    limit = None if mode == "all" or prefix is None else max(0, prefix)
    for index, candidate in enumerate(candidates):
        if limit is not None and index >= limit:
            yield candidate
            continue
        yield from case_forms(candidate)


def case_variant_count(
    total: int, mode: str = "off", prefix: Optional[int] = None
) -> int:
    """Largest number of candidates a scan tries with ``mode`` applied."""
    if mode == "off":
        return total
    expanded = (
        total if mode == "all" or prefix is None else min(total, max(0, prefix))
    )
    return total + 2 * expanded


MUTATION_MODES = ("off", "numbers", "symbols", "common", "all")

_DIGIT_TAILS = tuple(str(digit).encode("ascii") for digit in range(10))
_SYMBOL_TAILS = (
    b"!",
    b"@",
    b"#",
    b"$",
    b"%",
    b"&",
    b"*",
    b".",
    b"_",
    b"-",
    b"?",
    b"+",
)
_SYMBOL_NUMBER_TAILS = (b"1!", b"12!", b"123!", b"1.", b"123.")
_COMMON_NUMBER_TAILS = (
    tuple(f"{number:02d}".encode("ascii") for number in range(100))
    + (b"123", b"1234", b"12345", b"007", b"69")
    + tuple(str(year).encode("ascii") for year in range(1970, 2027))
)
_DOUBLED_SYMBOL_TAILS = (b"!!", b"123!!")
_LEET_SUBSTITUTIONS = {
    ord("a"): (ord("4"), ord("@")),
    ord("b"): (ord("8"),),
    ord("e"): (ord("3"),),
    ord("g"): (ord("9"),),
    ord("i"): (ord("1"),),
    ord("o"): (ord("0"),),
    ord("s"): (ord("5"), ord("$")),
    ord("t"): (ord("7"),),
}
_LEET_POSITION_LIMIT = 6
_LEET_MAX_FORMS = 72


def _tail_groups(mode: str) -> Tuple[Tuple[bytes, ...], ...]:
    """The suffix sets a mutation mode appends to every candidate."""
    if mode == "numbers":
        return (_DIGIT_TAILS,)
    if mode == "symbols":
        return (_SYMBOL_TAILS, _SYMBOL_NUMBER_TAILS)
    groups: Tuple[Tuple[bytes, ...], ...] = (
        _DIGIT_TAILS,
        _COMMON_NUMBER_TAILS,
        _SYMBOL_TAILS,
        _SYMBOL_NUMBER_TAILS,
    )
    if mode == "all":
        return groups + (_DOUBLED_SYMBOL_TAILS,)
    return groups


def mutation_factor(mode: str = "off") -> int:
    """Upper bound on the extra candidates ``mode`` adds per input form."""
    if mode not in MUTATION_MODES:
        raise WordlistError(f"unknown mutation mode: {mode}")
    if mode == "off":
        return 0
    tails = set()
    for group in _tail_groups(mode):
        tails.update(group)
    factor = len(tails)
    if mode == "all":
        factor += _LEET_MAX_FORMS
    return factor


def _leet_forms(candidate: bytes) -> List[bytes]:
    """One- and two-substitution leetspeak forms, bounded by position count."""
    positions = [
        index
        for index, byte in enumerate(candidate)
        if byte in _LEET_SUBSTITUTIONS
    ][:_LEET_POSITION_LIMIT]
    if not positions:
        return []
    forms = []
    for index in positions:
        for replacement in _LEET_SUBSTITUTIONS[candidate[index]]:
            forms.append(candidate[:index] + bytes([replacement]) + candidate[index + 1:])
    for first_index, first in enumerate(positions):
        for second in positions[first_index + 1:]:
            for first_replacement in _LEET_SUBSTITUTIONS[candidate[first]]:
                for second_replacement in _LEET_SUBSTITUTIONS[candidate[second]]:
                    mutated = bytearray(candidate)
                    mutated[first] = first_replacement
                    mutated[second] = second_replacement
                    forms.append(bytes(mutated))
    return forms


def mutation_forms(candidate: bytes, mode: str = "off") -> List[bytes]:
    """Return ``candidate`` plus the number/symbol forms ``mode`` allows.

    The bare candidate always comes first. Non-ASCII candidates are returned
    unchanged: appending an ASCII tail to them is still safe, but leetspeak and
    symbols are skipped because the tails are calibrated for ASCII passwords.
    """
    if mode not in MUTATION_MODES:
        raise WordlistError(f"unknown mutation mode: {mode}")
    if mode == "off":
        return [candidate]
    if not candidate.isascii():
        return [candidate]
    forms = [candidate]
    seen = {candidate}
    if mode == "all":
        for form in _leet_forms(candidate):
            if form not in seen:
                seen.add(form)
                forms.append(form)
    for group in _tail_groups(mode):
        for tail in group:
            form = candidate + tail
            if form not in seen:
                seen.add(form)
                forms.append(form)
    return forms


def iter_expansions(
    candidates: Iterator[bytes],
    case_mode: str = "off",
    mutation_mode: str = "off",
    prefix: Optional[int] = None,
) -> Iterator[bytes]:
    """Apply case variants and mutations to the same base candidate.

    Both layers expand only the first ``prefix`` candidates (the small tier)
    unless their mode is ``all``, so a medium-tier scan does not compound two
    different prefix rules.
    """
    if case_mode not in CASE_MODES:
        raise WordlistError(f"unknown case variant mode: {case_mode}")
    if mutation_mode not in MUTATION_MODES:
        raise WordlistError(f"unknown mutation mode: {mutation_mode}")
    if case_mode == "off" and mutation_mode == "off":
        yield from candidates
        return
    for index, candidate in enumerate(candidates):
        in_prefix = prefix is None or index < prefix
        if case_mode == "off":
            forms: Tuple[bytes, ...] = (candidate,)
        elif case_mode == "all" or in_prefix:
            forms = tuple(case_forms(candidate))
        else:
            forms = (candidate,)
        for form in forms:
            if mutation_mode == "off":
                yield form
            elif mutation_mode == "all" or in_prefix:
                yield from mutation_forms(form, mutation_mode)
            else:
                yield form


def expansion_count(
    total: int,
    case_mode: str = "off",
    mutation_mode: str = "off",
    prefix: Optional[int] = None,
) -> int:
    """Upper bound on the candidates :func:`iter_expansions` can emit."""
    if case_mode not in CASE_MODES:
        raise WordlistError(f"unknown case variant mode: {case_mode}")
    if mutation_mode not in MUTATION_MODES:
        raise WordlistError(f"unknown mutation mode: {mutation_mode}")
    expanded = total if prefix is None else min(total, max(0, prefix))
    case_base = total if (case_mode == "all" or prefix is None) else expanded
    case_forms_total = total + (2 * case_base if case_mode != "off" else 0)
    if mutation_mode == "off":
        return case_forms_total
    mutated_base = total if (mutation_mode == "all" or prefix is None) else expanded
    mutated_forms = mutated_base * (3 if case_mode != "off" else 1)
    return case_forms_total + mutation_factor(mutation_mode) * mutated_forms


def _iter_seed_variants(seeds: List[bytes], limit: int) -> Iterator[bytes]:
    """Yield exactly ``limit`` unique bare-seed and suffixed candidates.

    Each case form of a seed is tried bare first (so ``patty``, ``Patty`` and
    ``PATTY`` are candidates, not only their numbered forms), then with the
    six-digit suffixes. The suffix is fixed-width, so two different seeds
    cannot collide even when one seed is a prefix of another. Seed ownership is
    de-duplicated by the caller, which keeps the whole generated tier unique.
    """
    if limit <= 0:
        return
    forms = [form for seed in seeds for form in _seed_forms(seed)]
    if not forms:
        raise WordlistError("generated tier has no seed names")
    capacity = len(forms) * (1 + GENERATED_SUFFIX_LIMIT)
    if limit > capacity:
        raise WordlistError(
            f"generated tier needs {limit:,} candidates but its seeds only "
            f"support {capacity:,}"
        )
    emitted = 0
    for form in forms:
        yield form
        emitted += 1
        if emitted >= limit:
            return
    for suffix in range(GENERATED_SUFFIX_LIMIT):
        code = f"{suffix:06d}".encode("ascii")
        for form in forms:
            yield form + code
            emitted += 1
            if emitted >= limit:
                return


def _generated_pools() -> Tuple[List[bytes], List[bytes], List[bytes]]:
    """Load disjoint English, name, and other-language seed pools."""
    seen = set()
    names = _load_seeds(NAMES_PATH, seen, comments=True)
    english = _load_seeds(WORDLIST_DIR / "dictionary-english.txt", seen)
    other_groups = [
        _load_seeds(WORDLIST_DIR / name, seen)
        for name in (
            "dictionary-indonesian.txt",
            "dictionary-hindi.txt",
            "dictionary-russian.txt",
            "dictionary-ukrainian.txt",
        )
    ]
    return english, names, _round_robin(other_groups)


def _iter_generated(tier: str) -> Iterator[bytes]:
    """Yield generated candidates after the bundled medium prefix."""
    total = GENERATED_TIERS[tier]
    medium = tier_count("medium")
    remaining = total - medium
    english_quota = remaining // 2
    names_quota = remaining // 4
    other_quota = remaining - english_quota - names_quota
    english, names, other = _generated_pools()
    yield from _iter_seed_variants(english, english_quota)
    yield from _iter_seed_variants(names, names_quota)
    yield from _iter_seed_variants(other, other_quota)


def iter_tier(tier: str) -> Iterator[bytes]:
    """Stream every candidate in ``tier`` without loading it into memory."""
    if tier not in TIERS:
        raise WordlistError(f"unknown wordlist tier: {tier}")
    if tier in GENERATED_TIERS:
        # The common list is the first file in medium, so it is tried before
        # any generated candidate.
        yield from iter_tier("medium")
        yield from _iter_generated(tier)
        return
    for path in tier_files(tier):
        if path.suffix == ".gz":
            if not path.is_file():
                raise WordlistError(f"wordlist not found: {path}")
            try:
                with gzip.open(path, "rb") as handle:
                    for line in handle:
                        candidate = line.rstrip(b"\r\n")
                        if candidate:
                            yield candidate
            except (OSError, EOFError, zlib.error) as exc:
                raise WordlistError(
                    f"cannot read wordlist: {path}: {exc}"
                ) from exc
            continue
        yield from iter_file(path, comments=False)
