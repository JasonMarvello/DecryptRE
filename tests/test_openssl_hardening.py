"""Hardening tests: malformed, random and mutated OpenSSL blobs never crash."""

import base64
import random

import pytest

from decryptre import auto_detect, openssl_compat
from decryptre.cli import _format_hint, main

MESSAGE = "The quick brown fox jumps over the lazy dog."
PASSPHRASE = "pass123"


def _aes_blob(text=MESSAGE, passphrase=PASSPHRASE):
    salt = b"salty123"
    key, iv = openssl_compat.evp_bytes_to_key(passphrase.encode(), salt, 32, 16)
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    body = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(text.encode(), 16))
    return base64.b64encode(b"Salted__" + salt + body).decode("ascii")


def _valid_plaintext(text: str) -> bool:
    """Every accepted OpenSSL plaintext must satisfy the module's rules."""
    if not text:
        return False
    if len(text) < 20 and not text.isascii():
        return False
    if any(ord(ch) < 32 and ch not in "\r\n\t" for ch in text):
        return False
    return openssl_compat.printable_ratio(text) >= 0.98


MALFORMED = [
    "",
    " ",
    "Salted__",
    "U2FsdGVkX1",
    "U2FsdGVkX1/",
    "U2FsdGVkX1/BgMIekKoYhbG+zWYlJr2X!!!!",
    "not base64 at all",
    "é" * 40,
    "\x00\x01\x02Salted__",
    base64.b64encode(b"Salted__").decode(),
    base64.b64encode(b"Salted__" + b"12345678").decode(),
]


@pytest.mark.parametrize("token", MALFORMED)
def test_malformed_values_are_rejected_quietly(token):
    assert openssl_compat.looks_like(token) is False
    assert openssl_compat.try_decrypt(token, PASSPHRASE) is None
    assert openssl_compat.dictionary_attack(token, ["x", "y"]) == []


def test_short_salt_is_rejected():
    token = base64.b64encode(b"Salted__" + b"short").decode()
    assert openssl_compat.looks_like(token) is False
    assert openssl_compat.try_decrypt(token, PASSPHRASE) is None


def test_one_byte_body_is_flagged_but_not_opened():
    # A complete salt with a useless ciphertext is shape-recognizable, but
    # must never be reported as decrypted.
    token = base64.b64encode(b"Salted__" + b"12345678" + b"\x00").decode()
    assert openssl_compat.looks_like(token) is True
    assert openssl_compat.try_decrypt(token, PASSPHRASE) is None
    assert openssl_compat.dictionary_attack(token, [PASSPHRASE]) == []


def test_block_misalignment_never_raises():
    # 17 bytes of body: not a multiple of any block size in use.
    token = base64.b64encode(b"Salted__" + b"12345678" + bytes(17)).decode()
    assert openssl_compat.try_decrypt(token, PASSPHRASE) is None
    assert openssl_compat.dictionary_attack(token, ["pass123"]) == []


def test_random_payloads_never_crash_or_misreport():
    rng = random.Random(20261121)
    for _ in range(150):
        salt = bytes(rng.randrange(256) for _ in range(8))
        body = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 200)))
        token = base64.b64encode(b"Salted__" + salt + body).decode()
        hit = openssl_compat.try_decrypt(token, "guess")
        if hit is not None:
            assert _valid_plaintext(hit[0])


def test_single_byte_mutations_never_crash():
    blob = _aes_blob()
    raw = bytearray(base64.b64decode(blob))
    for index in range(len(raw)):
        mutated = bytearray(raw)
        mutated[index] ^= 0xFF
        token = base64.b64encode(bytes(mutated)).decode()
        # The important part: no exception and no malformed result.
        hit = openssl_compat.try_decrypt(token, PASSPHRASE)
        if hit is not None:
            assert _valid_plaintext(hit[0])


def test_wrong_passphrase_and_empty_passphrase():
    blob = _aes_blob()
    assert openssl_compat.try_decrypt(blob, "wrong") is None
    assert openssl_compat.try_decrypt(blob, "") is None


def test_wordlist_noise_is_tolerated():
    blob = _aes_blob()
    words = ["", "  ", PASSPHRASE, PASSPHRASE, "  " + PASSPHRASE + "  ", "ümlaut"]
    results = openssl_compat.dictionary_attack(blob, words, top=2)
    assert [result.text for result in results] == [MESSAGE]


def test_progress_not_called_for_invalid_blob():
    calls = []
    openssl_compat.dictionary_attack(
        "not a blob", ["a", "b"], progress=lambda *args: calls.append(args)
    )
    assert calls == []


def test_wrapped_base64_blob_opens_in_auto_mode():
    inner = _aes_blob()
    outer = base64.b64encode(inner.encode()).decode()
    results = auto_detect.detect(outer, top=1, passphrase=PASSPHRASE)
    assert results[0].text == MESSAGE
    assert results[0].verified is True


def test_raw_binary_blob_from_a_file(tmp_path, capsys):
    salt = b"\xffalty123"
    key, iv = openssl_compat.evp_bytes_to_key(PASSPHRASE.encode(), salt, 32, 16)
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    body = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(MESSAGE.encode(), 16))
    path = tmp_path / "blob.bin"
    path.write_bytes(b"Salted__" + salt + body)
    assert main(["decrypt", "--input", str(path), "--key", PASSPHRASE, "--no-wordlist"]) == 0
    out = capsys.readouterr().out
    assert MESSAGE in out
    assert "OpenSSL" in out


def test_surrogateescaped_text_is_decoded():
    raw = base64.b64decode(_aes_blob())
    text = raw.decode("utf-8", "surrogateescape")
    hit = openssl_compat.try_decrypt(text, PASSPHRASE)
    assert hit is not None
    assert hit[0] == MESSAGE


def test_hints_wrap_without_long_lines():
    blob = _aes_blob()
    for had_key in (False, True):
        hint = _format_hint(blob, had_key)
        assert hint is not None
        assert max(len(line) for line in hint.splitlines()) <= 78
        assert "OpenSSL" in hint


def test_detect_fuzz_never_crashes():
    rng = random.Random(7)
    alphabet = "abcXYZ019+/=_- \n"
    for _ in range(60):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 80)))
        auto_detect.detect(
            text, max_depth=2, top=2, wordlist=[], include_substitution=False
        )


def test_explicit_method_rejects_non_blob():
    with pytest.raises(SystemExit) as excinfo:
        main(["decrypt", "--input", "hello", "--method", "openssl", "--key", "x"])
    assert "wrong passphrase" in str(excinfo.value)


def test_wrapped_base64_blob_opens_in_method_mode():
    blob = _aes_blob()
    wrapped = "\n".join(
        blob[index:index + 40] for index in range(0, len(blob), 40)
    )
    hit = openssl_compat.try_decrypt(wrapped, PASSPHRASE)
    assert hit is not None
    assert hit[0] == MESSAGE
