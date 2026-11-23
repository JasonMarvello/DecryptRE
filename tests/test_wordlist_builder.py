"""The local-only large-tier builder deduplicates across shipped lists."""

import gzip
import importlib.util
import json
from pathlib import Path

from decryptre import wordlist

ROOT = Path(__file__).resolve().parent.parent


def _load_builder():
    path = ROOT / "tools" / "build_wordlists.py"
    spec = importlib.util.spec_from_file_location("build_wordlists", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_fetch_rockyou_dedupes_against_medium_and_within_rockyou(
    monkeypatch, tmp_path, capsys
):
    base = tmp_path / "wordlists"
    base.mkdir()
    (base / "common.txt").write_bytes(b"alpha\nbeta\n")
    (base / "extra.txt").write_bytes(b"gamma\ndelta\n")
    (base / "manifest.json").write_text(
        json.dumps(
            {
                "version": 1,
                "tiers": {
                    "small": {"files": ["common.txt"], "count": 2},
                    "medium": {
                        "files": ["common.txt", "extra.txt"],
                        "count": 4,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    source = tmp_path / "rockyou.txt"
    source.write_bytes(b"delta\nepsilon\nepsilon\nzeta\n")

    monkeypatch.setattr(wordlist, "WORDLIST_DIR", base)
    monkeypatch.setattr(wordlist, "MANIFEST_PATH", base / "manifest.json")
    monkeypatch.setattr(
        wordlist, "ROCKYOU_META_PATH", base / "rockyou-large.json"
    )

    builder = _load_builder()
    monkeypatch.setattr(builder, "WORDLIST_DIR", base)
    monkeypatch.setattr(
        builder, "ROCKYOU_GZ", base / "rockyou-large.txt.gz"
    )
    monkeypatch.setattr(
        builder, "ROCKYOU_META", base / "rockyou-large.json"
    )

    assert builder.fetch_rockyou(str(source), assume_yes=True, force=False) == 0
    capsys.readouterr()

    with gzip.open(base / "rockyou-large.txt.gz", "rb") as handle:
        assert handle.read() == b"epsilon\nzeta\n"
    meta = json.loads((base / "rockyou-large.json").read_text())
    assert meta["count"] == 2
    assert meta["raw_lines"] == 4
    assert meta["duplicates_removed"] == 2
    assert wordlist.tier_count("large") == 6
    assert list(wordlist.iter_tier("large"))[-2:] == [b"epsilon", b"zeta"]


def test_verify_rejects_duplicates_across_shipped_files(
    monkeypatch, tmp_path
):
    base = tmp_path / "wordlists"
    base.mkdir()
    (base / "common.txt").write_bytes(b"alpha\nbeta\n")
    (base / "extra.txt").write_bytes(b"beta\ngamma\n")
    (base / "manifest.json").write_text(
        json.dumps(
            {
                "version": 1,
                "tiers": {
                    "small": {"files": ["common.txt"], "count": 2},
                    "medium": {
                        "files": ["common.txt", "extra.txt"],
                        "count": 3,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(wordlist, "WORDLIST_DIR", base)
    monkeypatch.setattr(wordlist, "MANIFEST_PATH", base / "manifest.json")

    builder = _load_builder()
    try:
        builder.verify(write_manifest=False)
    except SystemExit as exc:
        assert "duplicate" in str(exc)
    else:  # pragma: no cover - the assertion is the test
        raise AssertionError("verify accepted duplicate wordlist entries")
