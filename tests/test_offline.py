"""DecryptRE promises to be fully offline. This test enforces that promise."""

from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "decryptre"

FORBIDDEN = (
    "import requests",
    "import urllib.request",
    "from urllib.request",
    "import httpx",
    "import aiohttp",
    "import socket",
    "http.client",
)


def test_package_has_no_network_imports():
    offenders = []
    for path in PACKAGE.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        for needle in FORBIDDEN:
            if needle in source:
                offenders.append(f"{path.relative_to(PACKAGE)}: {needle}")
    assert not offenders, "network code found: " + ", ".join(offenders)


def test_bundled_data_is_present():
    assert (PACKAGE / "wordlists" / "common-passwords.txt").is_file()
    assert (PACKAGE / "wordlists" / "manifest.json").is_file()
    assert (PACKAGE / "data" / "trigrams.txt").is_file()
