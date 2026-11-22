"""Edge cases for every method, the scorer and the presentation layer.

These are the cases that used to fail silently: empty input, binary data,
very short ciphertext, non-English text, long text and a known passphrase.
"""

import pytest

from decryptre import auto_detect, classical, encodings, modern_crypto
from decryptre.cli import main, read_input
from decryptre.scorer import (
    NON_LATIN_SCORE,
    SHORT_TEXT_SCORE,
    printable_ratio,
    score_text,
)

MESSAGE = "The quick brown fox jumps over the lazy dog."
PASSPHRASE = "hello123"
CJK = "这是一个秘密消息，用来测试评分器。"
BINARY = "".join(chr(value) for value in range(256))

ENCODING_NAMES = list(encodings.ENCODINGS)
CLASSICAL_METHODS = ["caesar", "atbash", "vigenere", "railfence", "substitution"]
MODERN_METHODS = ["fernet", "aes", "des3"]
ALL_METHODS = ENCODING_NAMES + CLASSICAL_METHODS + ["xor", "rot13"] + MODERN_METHODS


def run_cli(argv):
    """Return the exit code, accepting a deliberate SystemExit with a message."""
    try:
        return main(argv)
    except SystemExit as exc:
        assert str(exc).strip(), "a deliberate error must explain itself"
        return 1


# ---------------------------------------------------------------------------
# Scorer: no silent failure on input it cannot judge
# ---------------------------------------------------------------------------

def test_unicode_counts_as_printable():
    assert printable_ratio(CJK) == 1.0
    assert printable_ratio("café naïve résumé") == 1.0


def test_non_latin_text_gets_its_own_score():
    assert score_text(CJK) == NON_LATIN_SCORE
    assert NON_LATIN_SCORE > -100


def test_short_text_is_not_scored_as_binary():
    assert score_text("Hi") == SHORT_TEXT_SCORE
    assert SHORT_TEXT_SCORE > -100


def test_empty_and_binary_still_score_badly():
    assert score_text("") == -1000.0
    assert score_text("\x00\x01\xff" * 10) < -100


# ---------------------------------------------------------------------------
# Every method: empty, binary and very short input must not traceback
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method", ALL_METHODS)
def test_empty_input_never_tracebacks(method, capsys):
    code = run_cli(
        ["decrypt", "--input", "", "--method", method,
         "--no-wordlist", "--no-substitution"]
    )
    assert code in (0, 1)


@pytest.mark.parametrize("method", ALL_METHODS)
def test_binary_input_never_tracebacks(method, capsys):
    code = run_cli(
        ["decrypt", "--input", BINARY, "--method", method,
         "--no-wordlist", "--no-substitution"]
    )
    assert code in (0, 1)


@pytest.mark.parametrize(
    "ciphertext,expected",
    [
        ("aGk=", "hi"),
        ("6869", "hi"),
        ("NBSWY3DP", "hello"),
    ],
)
def test_very_short_ciphertext(ciphertext, expected):
    results = auto_detect.detect(
        ciphertext, max_depth=2, top=3, include_substitution=False
    )
    assert any(candidate.text == expected for candidate in results)


def test_very_short_classical_ciphertext_does_not_crash():
    results = auto_detect.detect(
        "Kh", max_depth=2, top=3, include_substitution=False
    )
    assert results


def test_auto_handles_empty_input():
    results = auto_detect.detect("", max_depth=2, top=3, include_substitution=False)
    assert results[0].text == ""


def test_auto_handles_unscorable_non_english_input():
    results = auto_detect.detect(
        CJK, max_depth=2, top=3, include_substitution=False
    )
    assert results


def test_auto_decodes_non_english_base64():
    token = encodings.encode_base64(CJK)
    results = auto_detect.detect(
        token, max_depth=2, top=3, include_substitution=False
    )
    assert any(candidate.text == CJK for candidate in results)


def test_non_utf8_file_is_read_without_crashing(tmp_path, capsys):
    path = tmp_path / "blob.bin"
    path.write_bytes(bytes(range(256)))
    text = read_input(str(path))
    assert len(text) == 256
    assert run_cli(
        ["decrypt", "--input", str(path), "--no-wordlist", "--no-substitution"]
    ) == 0


def test_auto_preserves_long_text_instead_of_truncating():
    long_message = (MESSAGE + " ") * 300
    long_message = long_message.strip()
    token = classical.caesar_encrypt(long_message, 9)
    results = auto_detect.detect(token, max_depth=1, top=1)
    assert len(long_message) > 8000
    assert results[0].text == long_message


# ---------------------------------------------------------------------------
# Known passphrase reaches auto mode and is marked verified
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "alg,encrypt",
    [
        ("fernet", modern_crypto.encrypt_fernet),
        ("aes-gcm", lambda text, key: modern_crypto.encrypt_aes(text, key, mode="gcm")),
        ("aes-cbc", lambda text, key: modern_crypto.encrypt_aes(text, key, mode="cbc")),
        ("des3-cbc", modern_crypto.encrypt_des3),
    ],
)
def test_auto_with_passphrase_is_verified_and_first(alg, encrypt):
    token = encrypt(MESSAGE, PASSPHRASE)
    results = auto_detect.detect(token, top=1, passphrase=PASSPHRASE)
    assert results[0].text == MESSAGE
    assert results[0].verified is True
    assert results[0].params["alg"] == alg


def test_auto_without_passphrase_cannot_open_modern_crypto():
    token = modern_crypto.encrypt_aes(MESSAGE, PASSPHRASE)
    results = auto_detect.detect(
        token, top=3, wordlist=["nope"], include_substitution=False
    )
    assert not any(candidate.verified for candidate in results)


@pytest.mark.parametrize(
    "encrypt",
    [
        modern_crypto.encrypt_fernet,
        lambda text, key: modern_crypto.encrypt_aes(text, key, mode="gcm"),
        lambda text, key: modern_crypto.encrypt_aes(text, key, mode="cbc"),
        modern_crypto.encrypt_des3,
    ],
)
def test_empty_plaintext_container_is_still_verified(encrypt):
    token = encrypt("", PASSPHRASE)
    results = auto_detect.detect(token, top=1, passphrase=PASSPHRASE)
    assert results[0].verified is True
    assert results[0].text == ""


# ---------------------------------------------------------------------------
# UI clarity
# ---------------------------------------------------------------------------

def test_cli_shows_method_params_and_plain_language_confidence(capsys):
    token = modern_crypto.encrypt_aes(MESSAGE, PASSPHRASE)
    assert main(["decrypt", "--input", token, "--key", PASSPHRASE]) == 0
    out = capsys.readouterr().out
    assert "AES-256-GCM" in out
    assert f'passphrase "{PASSPHRASE}"' in out
    assert "confidence: verified" in out
    assert MESSAGE in out


def test_cli_says_when_nothing_was_verified(capsys):
    assert main(
        ["decrypt", "--input", "xqzt vbnm klop wrty sdfg hjkl", "--no-substitution"]
    ) == 0
    out = capsys.readouterr().out
    assert "No verified result" in out


def test_methods_command_lists_every_method(capsys):
    assert main(["methods"]) == 0
    out = capsys.readouterr().out
    for name in (
        "base64", "base32", "base16", "url", "ascii85", "caesar", "atbash",
        "vigenere", "railfence", "substitution", "xor", "fernet", "aes", "des3",
    ):
        assert name in out
    assert "3DES" in out or "des3" in out


def test_help_explains_what_auto_and_key_do(capsys):
    with pytest.raises(SystemExit):
        main(["decrypt", "--help"])
    out = capsys.readouterr().out
    assert "peels layers" in out
    assert "verified by the cipher" in out
