"""The bundled passphrase tiers and streaming contract."""

import gzip
import json

import pytest

from decryptre import wordlist
from decryptre.cli import load_common_wordlist, load_wordlist


def test_common_wordlist_is_still_the_short_fast_list():
    assert len(load_common_wordlist()) == 10001


def test_bundled_dictionary_is_multilingual():
    words = set(load_wordlist())

    assert len(words) == 1_368_353
    # English (US and UK spellings), Indonesian, Hindi, Russian, Ukrainian.
    for word in (
        "password",
        "colour",
        "organise",
        "halo",
        "abad",
        "नमस्ते",
        "привет",
        "привіт",
    ):
        assert word in words


def test_medium_tier_is_globally_deduplicated():
    count = wordlist.tier_count("medium")
    unique = set(wordlist.iter_tier("medium"))

    assert count == 1_368_353
    assert len(unique) == count


def test_tier_stream_yields_bytes_and_preserves_non_utf8(tmp_path):
    path = tmp_path / "bytes.txt"
    path.write_bytes(b"\xffpass\n  spaced  \n# comment\n\n")

    assert list(wordlist.iter_file(path)) == [b"\xffpass", b"  spaced  "]


def test_large_tier_reports_how_to_install_it(monkeypatch, tmp_path):
    monkeypatch.setattr(
        wordlist, "ROCKYOU_META_PATH", tmp_path / "rockyou-large.json"
    )

    with pytest.raises(wordlist.WordlistError, match="not shipped"):
        wordlist.tier_count("large")
    with pytest.raises(wordlist.WordlistError, match="not shipped"):
        list(wordlist.iter_tier("large"))


def test_large_tier_streams_local_rockyou_after_medium(monkeypatch, tmp_path):
    base = tmp_path
    (base / "common.txt").write_bytes(b"alpha\nbeta\n")
    (base / "extra.txt").write_bytes(b"gamma\ndelta\n")
    with gzip.open(base / "rockyou-large.txt.gz", "wb") as handle:
        handle.write(b"delta\n#tag\nepsilon\n")
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
    (base / "rockyou-large.json").write_text(
        json.dumps({"file": "rockyou-large.txt.gz", "count": 3}),
        encoding="utf-8",
    )

    monkeypatch.setattr(wordlist, "WORDLIST_DIR", base)
    monkeypatch.setattr(wordlist, "MANIFEST_PATH", base / "manifest.json")
    monkeypatch.setattr(
        wordlist, "ROCKYOU_META_PATH", base / "rockyou-large.json"
    )

    assert wordlist.tier_count("large") == 7
    assert list(wordlist.iter_tier("large")) == [
        b"alpha",
        b"beta",
        b"gamma",
        b"delta",
        b"delta",
        b"#tag",
        b"epsilon",
    ]


def test_custom_wordlist_replaces_the_bundled_lists(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("# comment\none\n\ntwo\n", encoding="utf-8")

    assert load_wordlist(str(path)) == ["one", "two"]
