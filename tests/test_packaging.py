"""Packaging guards for the local-only large wordlist tier."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_wordlist_package_data_is_explicit():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "wordlists/*.txt" not in pyproject
    assert "wordlists/names.txt" in pyproject
    assert "rockyou" not in pyproject.lower()


def test_local_large_tier_files_are_gitignored():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert "decryptre/wordlists/rockyou-large.txt" in ignored
    assert "decryptre/wordlists/rockyou-large.txt.gz" in ignored
    assert "decryptre/wordlists/rockyou-large.json" in ignored
