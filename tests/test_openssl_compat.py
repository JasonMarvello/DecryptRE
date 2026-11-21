"""OpenSSL ``Salted__`` compatibility tests.

Includes the exact blob a user reported: OpenSSL 3DES-CBC, MD5 key
derivation, passphrase ``123``, plaintext ``hello``.
"""

import base64

import pytest
from Crypto.Cipher import AES, ARC4, DES, DES3
from Crypto.Util.Padding import pad

from decryptre import auto_detect, openssl_compat
from decryptre.cli import main

MESSAGE = "The quick brown fox jumps over the lazy dog."
PASSPHRASE = "pass123"
USER_BLOB = "U2FsdGVkX1/BgMIekKoYhbG+zWYlJr2X"


def encrypt_openssl(text, passphrase, cipher="aes-256-cbc", digest="md5"):
    """Build an OpenSSL-compatible salted blob for the tests."""
    salt = b"12345678"
    modules = {
        "aes-256-cbc": (AES, 32, 16),
        "aes-128-cbc": (AES, 16, 16),
        "des3-cbc": (DES3, 24, 8),
        "des-cbc": (DES, 8, 8),
        "rc4": (ARC4, 16, 0),
    }
    module, key_length, iv_length = modules[cipher]
    key, iv = openssl_compat.evp_bytes_to_key(
        passphrase.encode(), salt, key_length, iv_length, digest
    )
    data = text.encode("utf-8")
    if module is ARC4:
        body = ARC4.new(key).encrypt(data)
    else:
        body = module.new(key, module.MODE_CBC, iv).encrypt(
            pad(data, module.block_size)
        )
    return base64.b64encode(b"Salted__" + salt + body).decode("ascii")


@pytest.mark.parametrize(
    "cipher,digest",
    [
        ("aes-256-cbc", "md5"),
        ("aes-128-cbc", "sha256"),
        ("des3-cbc", "md5"),
        ("des-cbc", "sha256"),
        ("rc4", "md5"),
    ],
)
def test_openssl_roundtrip(cipher, digest):
    blob = encrypt_openssl(MESSAGE, PASSPHRASE, cipher, digest)
    assert openssl_compat.looks_like(blob)
    hit = openssl_compat.try_decrypt(blob, PASSPHRASE)
    assert hit is not None
    plain, alg = hit
    assert plain == MESSAGE
    assert alg.startswith("OpenSSL")


def test_reported_blob_is_3des_hello():
    assert openssl_compat.looks_like(USER_BLOB)
    hit = openssl_compat.try_decrypt(USER_BLOB, "123")
    assert hit is not None
    plain, alg = hit
    assert plain == "hello"
    assert "3DES" in alg


def test_wrong_passphrase_is_rejected():
    assert openssl_compat.try_decrypt(USER_BLOB, "124") is None


def test_auto_with_passphrase_marks_verified():
    results = auto_detect.detect(USER_BLOB, top=1, passphrase="123")
    assert results[0].text == "hello"
    assert results[0].verified is True
    assert results[0].method == "openssl"


def test_dictionary_attack_finds_passphrase():
    results = openssl_compat.dictionary_attack(USER_BLOB, ["nope", "123"], top=1)
    assert results
    assert results[0].text == "hello"
    assert results[0].params["passphrase"] == "123"
    assert results[0].verified is True


def test_cli_explicit_method(capsys):
    assert main(
        ["decrypt", "--input", USER_BLOB, "--method", "openssl", "--key", "123"]
    ) == 0
    out = capsys.readouterr().out
    assert "hello" in out
    assert "OpenSSL" in out
    assert "confidence: high" in out


def test_cli_auto_with_key(capsys):
    assert main(["decrypt", "--input", USER_BLOB, "--key", "123"]) == 0
    out = capsys.readouterr().out
    assert "hello" in out
    assert "OpenSSL" in out


def test_cli_explains_unopened_openssl_blob(capsys):
    assert main(
        ["decrypt", "--input", USER_BLOB, "--no-wordlist", "--no-substitution"]
    ) == 0
    out = capsys.readouterr().out
    assert "OpenSSL 'Salted__' blob" in out
    assert "--key" in out


def test_cli_explicit_method_without_key_needs_wordlist():
    with pytest.raises(SystemExit) as excinfo:
        main(["decrypt", "--input", USER_BLOB, "--method", "openssl", "--no-wordlist"])
    assert "need --key" in str(excinfo.value)
