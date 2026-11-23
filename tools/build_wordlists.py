#!/usr/bin/env python3
"""Verify shipped wordlist tiers and build the optional local RockYou tier.

The bundled small/medium lists are committed and shipped in the Python package.
The large tier is deliberately *not* packaged: this script downloads RockYou
locally, removes candidates already present in the shipped lists, and writes a
plain gzip + metadata file under ``decryptre/wordlists/``. Those two large-tier
files are ignored by Git and by setuptools.

Usage:
    python tools/build_wordlists.py --verify --write-manifest
    python tools/build_wordlists.py --fetch-rockyou
    python tools/build_wordlists.py --remove-rockyou
"""

import argparse
import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORDLIST_DIR = ROOT / "decryptre" / "wordlists"
sys.path.insert(0, str(ROOT))

from decryptre import wordlist  # noqa: E402

ROCKYOU_URL = (
    "https://github.com/danielmiessler/SecLists/raw/master/"
    "Passwords/Leaked-Databases/rockyou.txt.tar.gz"
)
ROCKYOU_FALLBACK_URL = "https://weakpass.com/download/90/rockyou.txt.gz"
ROCKYOU_GZ = WORDLIST_DIR / "rockyou-large.txt.gz"
ROCKYOU_META = WORDLIST_DIR / "rockyou-large.json"

NOTICE = """\
RockYou: provenance and ethics notice
-------------------------------------
RockYou is a password corpus from a 2009 data breach of the RockYou service.
It contains real people's passwords and other personal strings. It has no
explicit license; it is redistributed by security projects such as SecLists,
Kali Linux and Weakpass for defensive testing and research.

This script downloads it only because you asked. The resulting file stays on
this machine, is ignored by Git, and is excluded from DecryptRE's PyPI package.
Do not redistribute it or use it against accounts you do not own or have
permission to test. Prefer your own authorized corpus if you have one.

Source: {source}
Approximate download: 50 MB compressed, about 14.3 million lines.
"""


def _iter_lines_from_source(path: Path):
    """Yield lines from a plain, gzip or tar.gz RockYou download."""
    if tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as archive:
            member = next(
                (
                    item
                    for item in archive.getmembers()
                    if item.isfile() and Path(item.name).name == "rockyou.txt"
                ),
                None,
            )
            if member is None:
                raise SystemExit("error: download does not contain rockyou.txt")
            handle = archive.extractfile(member)
            if handle is None:
                raise SystemExit("error: cannot read rockyou.txt from archive")
            with handle:
                for line in handle:
                    yield line
        return

    with path.open("rb") as probe:
        is_gzip = probe.read(2) == b"\x1f\x8b"
    opener = gzip.open if is_gzip else open
    with opener(path, "rb") as handle:
        for line in handle:
            yield line


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _download(url: str, destination: Path) -> None:
    print(f"Downloading {url}")
    request = urllib.request.Request(
        url, headers={"User-Agent": "DecryptRE-wordlist-builder/1.0"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        total = int(response.headers.get("Content-Length") or 0)
        done = 0
        next_mark = 0
        with destination.open("wb") as output:
            while True:
                block = response.read(1024 * 256)
                if not block:
                    break
                output.write(block)
                done += len(block)
                if total and done >= next_mark:
                    print(
                        f"  {done / (1024 * 1024):.1f} / "
                        f"{total / (1024 * 1024):.1f} MiB",
                        file=sys.stderr,
                    )
                    next_mark += 10 * 1024 * 1024
        if total and done != total:
            raise SystemExit(
                f"error: download stopped at {done} of {total} bytes"
            )
    print(f"Downloaded {destination.stat().st_size:,} bytes")


def _confirm_download(source: str, assume_yes: bool) -> None:
    print(NOTICE.format(source=source))
    if assume_yes:
        print("--yes supplied; continuing.\n")
        return
    if not sys.stdin.isatty():
        raise SystemExit(
            "error: refusing a non-interactive download without --yes"
        )
    answer = input('Type "I understand" to continue: ').strip()
    if answer != "I understand":
        raise SystemExit("cancelled")


def verify(write_manifest: bool) -> int:
    """Check the shipped tiers for duplicates and refresh their manifest."""
    entries = {}
    seen = set()
    total = 0
    for tier in ("small", "medium"):
        files = wordlist.tier_files(tier)
        tier_total = 0
        file_data = []
        for path in files:
            if not path.is_file():
                raise SystemExit(f"error: missing bundled wordlist: {path}")
            count = 0
            for candidate in wordlist.iter_file(path, comments=False):
                count += 1
                if tier == "medium":
                    if candidate in seen:
                        raise SystemExit(
                            "error: duplicate across bundled medium lists: "
                            f"{candidate!r} ({path.name})"
                        )
                    seen.add(candidate)
            tier_total += count
            file_data.append(
                {
                    "name": path.name,
                    "count": count,
                    "bytes": path.stat().st_size,
                    "sha256": _sha256(path),
                }
            )
        entries[tier] = {
            "files": [item["name"] for item in file_data],
            "count": tier_total,
            "bytes": sum(item["bytes"] for item in file_data),
        }
        total = tier_total
        print(f"{tier:6} {tier_total:>12,} candidates  {len(files)} files")

    print(f"medium includes small: {entries['medium']['count'] == total:,}")
    print(f"unique medium candidates: {len(seen):,}")
    if len(seen) != entries["medium"]["count"]:
        raise SystemExit(
            "error: medium count does not match its unique candidate count"
        )

    if write_manifest:
        payload = {"version": 1, "tiers": entries}
        wordlist.MANIFEST_PATH.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote {wordlist.MANIFEST_PATH}")
    return 0


def fetch_rockyou(source: str, assume_yes: bool, force: bool) -> int:
    if ROCKYOU_GZ.exists() and not force:
        raise SystemExit(
            f"error: {ROCKYOU_GZ} already exists; pass --force to rebuild"
        )
    _confirm_download(source, assume_yes)

    with tempfile.TemporaryDirectory(prefix="decryptre-rockyou-") as temp:
        temp_dir = Path(temp)
        if source.startswith(("http://", "https://")):
            download = temp_dir / "rockyou.download"
            try:
                _download(source, download)
            except Exception as exc:
                if "raw.githubusercontent.com" in source or "github.com" in source:
                    print(
                        f"Primary download failed ({exc}); trying {ROCKYOU_FALLBACK_URL}",
                        file=sys.stderr,
                    )
                    source = ROCKYOU_FALLBACK_URL
                    _download(source, download)
                else:
                    raise
        else:
            download = Path(source)
            if not download.is_file():
                raise SystemExit(f"error: source file not found: {download}")

        database = temp_dir / "dedupe.sqlite3"
        db = sqlite3.connect(str(database))
        try:
            db.execute("PRAGMA journal_mode=OFF")
            db.execute("PRAGMA synchronous=OFF")
            db.execute("PRAGMA cache_size=-200000")
            db.execute(
                "CREATE TABLE words(value BLOB PRIMARY KEY) WITHOUT ROWID"
            )
            db.execute(
                "CREATE TABLE new(seq INTEGER PRIMARY KEY, value BLOB UNIQUE)"
            )
            shipped = []
            for candidate in wordlist.iter_tier("medium"):
                shipped.append((candidate,))
                if len(shipped) >= 10_000:
                    db.executemany(
                        "INSERT OR IGNORE INTO words(value) VALUES (?)", shipped
                    )
                    shipped.clear()
            if shipped:
                db.executemany(
                    "INSERT OR IGNORE INTO words(value) VALUES (?)", shipped
                )
            db.commit()
            print(f"Indexed {db.total_changes:,} shipped candidates")

            raw_lines = 0
            batch = []
            for line in _iter_lines_from_source(download):
                candidate = line.rstrip(b"\r\n")
                if not candidate:
                    continue
                batch.append((candidate,))
                raw_lines += 1
                if len(batch) >= 10_000:
                    db.executemany(
                        "INSERT OR IGNORE INTO new(value) VALUES (?)", batch
                    )
                    batch.clear()
                    db.commit()
                if raw_lines % 1_000_000 == 0:
                    print(
                        f"  read {raw_lines:,} RockYou lines",
                        file=sys.stderr,
                    )
            if batch:
                db.executemany(
                    "INSERT OR IGNORE INTO new(value) VALUES (?)", batch
                )
            db.commit()

            unique = db.execute(
                "SELECT COUNT(*) FROM new n WHERE NOT EXISTS "
                "(SELECT 1 FROM words w WHERE w.value = n.value)"
            ).fetchone()[0]
            if not unique:
                raise SystemExit("error: no new candidates were found")

            tmp_gz = ROCKYOU_GZ.with_name(ROCKYOU_GZ.name + ".tmp")
            written = 0
            with tmp_gz.open("wb") as raw_output:
                with gzip.GzipFile(
                    fileobj=raw_output, mode="wb", compresslevel=6, mtime=0
                ) as output:
                    cursor = db.execute(
                        "SELECT n.value FROM new n WHERE NOT EXISTS "
                        "(SELECT 1 FROM words w WHERE w.value = n.value) "
                        "ORDER BY n.seq"
                    )
                    for (candidate,) in cursor:
                        output.write(candidate + b"\n")
                        written += 1
            if written != unique:
                raise SystemExit(
                    f"error: wrote {written:,} of {unique:,} unique candidates"
                )

            os.replace(tmp_gz, ROCKYOU_GZ)
            meta = {
                "file": ROCKYOU_GZ.name,
                "count": unique,
                "raw_lines": raw_lines,
                "duplicates_removed": raw_lines - unique,
                "source": source,
                "retrieved": date.today().isoformat(),
                "sha256": _sha256(ROCKYOU_GZ),
                "bytes": ROCKYOU_GZ.stat().st_size,
                "license": "No explicit license; 2009 RockYou breach corpus",
            }
            ROCKYOU_META.write_text(
                json.dumps(meta, indent=2) + "\n", encoding="utf-8"
            )
            print(
                f"Wrote {ROCKYOU_GZ} ({unique:,} new candidates, "
                f"{ROCKYOU_GZ.stat().st_size / (1024 * 1024):.1f} MiB)"
            )
            print(f"Wrote {ROCKYOU_META}")
            print(
                "Large tier total: "
                f"{wordlist.tier_count('large'):,} candidates"
            )
        finally:
            db.close()
    return 0


def remove_rockyou() -> int:
    removed = []
    for path in (ROCKYOU_GZ, ROCKYOU_META):
        if path.exists():
            path.unlink()
            removed.append(path.name)
    print("Removed " + ", ".join(removed) if removed else "Nothing to remove")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--verify",
        action="store_true",
        help="verify shipped tiers and optionally rewrite the manifest",
    )
    action.add_argument(
        "--fetch-rockyou",
        action="store_true",
        help="download and deduplicate the optional local large tier",
    )
    action.add_argument(
        "--remove-rockyou",
        action="store_true",
        help="delete the local large-tier files",
    )
    parser.add_argument(
        "--write-manifest",
        action="store_true",
        help="with --verify, rewrite decryptre/wordlists/manifest.json",
    )
    parser.add_argument(
        "--source",
        default=ROCKYOU_URL,
        help="RockYou URL or local .txt/.gz/.tar.gz file",
    )
    parser.add_argument(
        "--yes", action="store_true", help="accept the notice non-interactively"
    )
    parser.add_argument(
        "--force", action="store_true", help="overwrite an existing large tier"
    )
    args = parser.parse_args(argv)

    if args.remove_rockyou:
        return remove_rockyou()
    if args.fetch_rockyou:
        return fetch_rockyou(args.source, args.yes, args.force)
    return verify(args.write_manifest or not args.verify)


if __name__ == "__main__":
    raise SystemExit(main())
