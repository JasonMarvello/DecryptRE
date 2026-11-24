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
from typing import Dict, Iterator, List, Tuple

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


def _iter_seed_variants(seeds: List[bytes], limit: int) -> Iterator[bytes]:
    """Yield exactly ``limit`` unique seed + six-digit-suffix candidates.

    The suffix is fixed-width, so two different seeds cannot collide even when
    one seed is a prefix of another. Seed ownership is de-duplicated by the
    caller, which keeps the whole generated tier unique.
    """
    if limit <= 0:
        return
    forms = [form for seed in seeds for form in _seed_forms(seed)]
    if not forms:
        raise WordlistError("generated tier has no seed names")
    capacity = len(forms) * GENERATED_SUFFIX_LIMIT
    if limit > capacity:
        raise WordlistError(
            f"generated tier needs {limit:,} candidates but its seeds only "
            f"support {capacity:,}"
        )
    emitted = 0
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
