"""Encodings (not encryption): Base64, Base32, Base16/hex, URL, ASCII85.

These are reversible ways of writing bytes as text. They offer no secrecy,
which is exactly why they are the first layer of many CTF puzzles.
"""

import base64
import binascii
import re
import urllib.parse
from typing import Callable, Dict, Tuple


class DecodeError(ValueError):
    """Raised when a string cannot be decoded with a given encoding."""


_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F\s]+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_B32_RE = re.compile(r"^[A-Za-z2-7=\s]+$")


def _bytes_to_text(raw: bytes) -> str:
    """Turn decoded bytes into text, preferring UTF-8."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        # latin-1 never fails and keeps every byte value, which is useful
        # when a layer is actually binary (e.g. XOR output).
        return raw.decode("latin-1")


def _strip_space(text: str) -> str:
    return "".join(text.split())


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------

def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def decode_base64(text: str) -> str:
    cleaned = _strip_space(text)
    if not cleaned:
        raise DecodeError("empty input")
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    cleaned += "=" * ((-len(cleaned)) % 4)
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(f"not valid Base64: {exc}") from exc
    return _bytes_to_text(raw)


# ---------------------------------------------------------------------------
# Base32
# ---------------------------------------------------------------------------

def encode_base32(text: str) -> str:
    return base64.b32encode(text.encode("utf-8")).decode("ascii")


def decode_base32(text: str) -> str:
    cleaned = _strip_space(text).upper()
    if not cleaned:
        raise DecodeError("empty input")
    cleaned += "=" * ((-len(cleaned)) % 8)
    try:
        raw = base64.b32decode(cleaned, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(f"not valid Base32: {exc}") from exc
    return _bytes_to_text(raw)


# ---------------------------------------------------------------------------
# Base16 / hex
# ---------------------------------------------------------------------------

def encode_base16(text: str) -> str:
    return text.encode("utf-8").hex()


def decode_base16(text: str) -> str:
    cleaned = _strip_space(text)
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    if not cleaned or len(cleaned) % 2:
        raise DecodeError("hex input must have an even number of digits")
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise DecodeError(f"not valid hex: {exc}") from exc
    return _bytes_to_text(raw)


# ---------------------------------------------------------------------------
# URL / percent encoding
# ---------------------------------------------------------------------------

def encode_url(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def decode_url(text: str) -> str:
    return urllib.parse.unquote_plus(text)


# ---------------------------------------------------------------------------
# ASCII85
# ---------------------------------------------------------------------------

def encode_ascii85(text: str) -> str:
    return base64.a85encode(text.encode("utf-8")).decode("ascii")


def decode_ascii85(text: str) -> str:
    cleaned = _strip_space(text)
    if cleaned.startswith("<~"):
        cleaned = cleaned[2:]
    if cleaned.endswith("~>"):
        cleaned = cleaned[:-2]
    if not cleaned:
        raise DecodeError("empty input")
    try:
        raw = base64.a85decode(cleaned, adobe=False)
    except (binascii.Error, ValueError) as exc:
        # Some tools wrap output in Adobe delimiters; retry that way.
        try:
            raw = base64.a85decode(cleaned, adobe=True)
        except (binascii.Error, ValueError):
            raise DecodeError(f"not valid ASCII85: {exc}") from exc
    return _bytes_to_text(raw)


# ---------------------------------------------------------------------------
# Registry and guessing helpers
# ---------------------------------------------------------------------------

ENCODINGS: Dict[str, Tuple[Callable[[str], str], Callable[[str], str]]] = {
    "base64": (encode_base64, decode_base64),
    "base32": (encode_base32, decode_base32),
    "base16": (encode_base16, decode_base16),
    "url": (encode_url, decode_url),
    "ascii85": (encode_ascii85, decode_ascii85),
}

# Friendly aliases accepted on the command line.
ALIASES = {
    "b64": "base64",
    "b32": "base32",
    "b16": "base16",
    "hex": "base16",
    "a85": "ascii85",
    "percent": "url",
    "urlencode": "url",
}


def resolve_name(name: str) -> str:
    key = name.strip().lower()
    key = ALIASES.get(key, key)
    if key not in ENCODINGS:
        raise KeyError(name)
    return key


def encode(text: str, name: str) -> str:
    return ENCODINGS[resolve_name(name)][0](text)


def decode(text: str, name: str) -> str:
    return ENCODINGS[resolve_name(name)][1](text)


def looks_like(text: str, name: str) -> bool:
    """Cheap shape check used before trying an expensive decode."""
    cleaned = _strip_space(text)
    if len(cleaned) < 4:
        return False
    if name == "base64":
        # Four characters is enough for "hi"; short tokens are still cheap to
        # try, and a failed decode is discarded immediately.
        return len(cleaned) >= 4 and bool(_B64_RE.match(cleaned)) and len(cleaned) % 4 != 1
    if name == "base32":
        return len(cleaned) >= 8 and bool(_B32_RE.match(cleaned))
    if name == "base16":
        return len(cleaned) >= 4 and len(cleaned) % 2 == 0 and bool(_HEX_RE.match(cleaned))
    if name == "url":
        return "%" in cleaned
    if name == "ascii85":
        return len(cleaned) >= 5 and all(33 <= ord(c) <= 117 for c in cleaned)
    return True
