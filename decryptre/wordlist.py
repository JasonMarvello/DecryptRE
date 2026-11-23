"""Tiered, streaming access to bundled wordlists.

Small and medium tiers ship with DecryptRE. The optional large tier adds a
locally built RockYou file and is never part of the installed package.
Candidate lines are yielded as raw bytes: passphrases are byte strings, and
decoding them as UTF-8 first would change non-ASCII entries.
"""

import gzip
import json
from pathlib import Path
from typing import Dict, Iterator, List

WORDLIST_DIR = Path(__file__).parent / "wordlists"
MANIFEST_PATH = WORDLIST_DIR / "manifest.json"
ROCKYOU_META_PATH = WORDLIST_DIR / "rockyou-large.json"
TIERS = ("small", "medium", "large")


class WordlistError(ValueError):
    """Raised when a tier or wordlist file cannot be used."""


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
    manifest = _manifest()
    tiers = manifest["tiers"]
    if tier == "large":
        medium = tiers.get("medium")
        if not isinstance(medium, dict):
            raise WordlistError("wordlist manifest has no medium tier")
        try:
            meta = json.loads(ROCKYOU_META_PATH.read_text(encoding="utf-8"))
            name = meta["file"]
            int(meta["count"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise WordlistError(
                "the large tier is not installed. From a source checkout, run "
                "`python tools/build_wordlists.py --fetch-rockyou` to download "
                "and deduplicate RockYou locally. It is not shipped with the "
                "PyPI package."
            ) from exc
        return [WORDLIST_DIR / name for name in medium["files"]] + [
            WORDLIST_DIR / str(name)
        ]

    entry = tiers.get(tier)
    if not isinstance(entry, dict) or not entry.get("files"):
        raise WordlistError(f"wordlist manifest has no {tier} tier")
    return [WORDLIST_DIR / str(name) for name in entry["files"]]


def tier_count(tier: str) -> int:
    """Number of candidates in ``tier``, from the manifest/local metadata."""
    if tier not in TIERS:
        raise WordlistError(f"unknown wordlist tier: {tier}")
    manifest = _manifest()
    if tier == "large":
        try:
            medium = int(manifest["tiers"]["medium"]["count"])
            meta = json.loads(ROCKYOU_META_PATH.read_text(encoding="utf-8"))
            return medium + int(meta["count"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise WordlistError(
                "the large tier is not installed. From a source checkout, run "
                "`python tools/build_wordlists.py --fetch-rockyou` to download "
                "and deduplicate RockYou locally. It is not shipped with the "
                "PyPI package."
            ) from exc
    try:
        return int(manifest["tiers"][tier]["count"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WordlistError(f"wordlist manifest has no count for {tier}") from exc


def iter_file(path: Path, *, comments: bool = True) -> Iterator[bytes]:
    """Yield non-empty lines from a plain wordlist as bytes.

    Custom lists use the documented ``#`` comment convention. Bundled tiers
    pass ``comments=False`` because a password such as ``#1`` is data, not a
    comment.
    """
    path = Path(path)
    if not path.is_file():
        raise WordlistError(f"wordlist not found: {path}")
    with path.open("rb") as handle:
        for line in handle:
            candidate = line.rstrip(b"\r\n")
            if not candidate:
                continue
            if comments and candidate.startswith(b"#"):
                continue
            yield candidate


def count_file(path: Path) -> int:
    """Count usable lines in a custom wordlist without keeping them."""
    return sum(1 for _ in iter_file(path))


def iter_tier(tier: str) -> Iterator[bytes]:
    """Stream every candidate in ``tier`` without loading it into memory."""
    for path in tier_files(tier):
        if path.suffix == ".gz":
            if not path.is_file():
                raise WordlistError(f"wordlist not found: {path}")
            with gzip.open(path, "rb") as handle:
                for line in handle:
                    candidate = line.rstrip(b"\r\n")
                    if candidate:
                        yield candidate
            continue
        yield from iter_file(path, comments=False)
