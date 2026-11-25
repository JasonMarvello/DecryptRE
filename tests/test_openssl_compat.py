"""OpenSSL ``Salted__`` compatibility tests.

Includes the exact blob a user reported: OpenSSL 3DES-CBC, MD5 key
derivation, passphrase ``123``, plaintext ``hello``.
"""

import base64
import hashlib

import pytest
from Crypto.Cipher import AES, ARC4, DES, DES3
from Crypto.Util.Padding import pad

from decryptre import auto_detect, openssl_compat
from decryptre.cli import main

MESSAGE = "The quick brown fox jumps over the lazy dog."
PASSPHRASE = "pass123"
USER_BLOB = "U2FsdGVkX1/BgMIekKoYhbG+zWYlJr2X"


def _key_schedule(blob, passphrase, cipher):
    """Return (attempt, spec, key, iv) for one cipher family."""
    labels = {
        "aes-256-cbc": "AES-256-CBC",
        "aes-128-cbc": "AES-128-CBC",
        "des3-cbc": "3DES-CBC",
        "des-cbc": "DES-CBC",
    }
    salt = b"12345678"
    key_lengths = {
        "aes-256-cbc": (32, 16),
        "aes-128-cbc": (16, 16),
        "des3-cbc": (24, 8),
        "des-cbc": (8, 8),
    }
    key_length, iv_length = key_lengths[cipher]
    key, iv = openssl_compat.evp_bytes_to_key(
        passphrase.encode(), salt, key_length, iv_length, "md5"
    )
    attempt = openssl_compat.prepare_legacy_attempt(blob)
    spec = next(item for item in attempt.ciphers if item.label == labels[cipher])
    return attempt, spec, key, iv


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
        ("aes-256-cbc", "sha1"),
        ("aes-256-cbc", "sha512"),
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


def _pbkdf2_blob(text, passphrase, digest="sha256", iterations=10_000):
    salt = b"12345678"
    material = hashlib.pbkdf2_hmac(
        digest, passphrase.encode(), salt, iterations, 48
    )
    body = AES.new(material[:32], AES.MODE_CBC, material[32:]).encrypt(
        pad(text.encode(), 16)
    )
    return base64.b64encode(b"Salted__" + salt + body).decode("ascii")


@pytest.mark.parametrize(
    "digest,iterations",
    [
        ("sha256", 10_000),
        ("sha256", 100_000),
        ("sha1", 10_000),
        ("sha512", 10_000),
    ],
)
def test_pbkdf2_variants_open_with_the_right_passphrase(digest, iterations):
    blob = _pbkdf2_blob(MESSAGE, PASSPHRASE, digest, iterations)
    hit = openssl_compat.try_decrypt(blob, PASSPHRASE)
    assert hit is not None
    assert hit[0] == MESSAGE
    assert "PBKDF2" in hit[1]


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
    assert "confidence: high (unauthenticated)" in out


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


def test_last_block_padding_check_accepts_every_cipher_family():
    text = "multi block plaintext for padding checks" * 20
    for cipher in ("aes-256-cbc", "aes-128-cbc", "des3-cbc", "des-cbc"):
        blob = encrypt_openssl(text, PASSPHRASE, cipher)
        attempt, spec, key, iv = _key_schedule(blob, PASSPHRASE, cipher)

        # The fast reject must accept a real key, including for the 8-byte
        # block ciphers, without changing the decrypted text.
        assert openssl_compat._valid_padding_block(
            attempt.body, key, iv, spec
        )
        decrypted = openssl_compat._decrypt_with(
            attempt.body, key, iv, "label", spec
        )
        assert decrypted == (text, "label")


def test_last_block_padding_check_rejects_a_wrong_key():
    blob = encrypt_openssl(MESSAGE, PASSPHRASE)
    attempt, spec, _key, iv = _key_schedule(blob, PASSPHRASE, "aes-256-cbc")
    wrong_key = b"\x01" * spec.key_length

    assert openssl_compat._decrypt_with(
        attempt.body, wrong_key, iv, "label", spec
    ) is None


def test_single_block_body_uses_the_iv_for_the_padding_check():
    # A one-block body has no previous ciphertext block; the IV supplies it.
    short = "hello"
    blob = encrypt_openssl(short, PASSPHRASE)
    attempt, spec, key, iv = _key_schedule(blob, PASSPHRASE, "aes-256-cbc")

    assert len(attempt.body) == spec.block_size
    assert openssl_compat._valid_padding_block(attempt.body, key, iv, spec)
    assert openssl_compat._valid_padding_block(
        attempt.body, key, b"\x00" * len(iv), spec
    ) is False


def test_large_multiblock_body_still_decrypts_exactly():
    text = "0123456789abcdef" * 8192  # 128 KiB, many blocks
    blob = encrypt_openssl(text, PASSPHRASE)
    attempt, spec, key, iv = _key_schedule(blob, PASSPHRASE, "aes-256-cbc")

    assert openssl_compat._decrypt_with(
        attempt.body, key, iv, "label", spec
    ) == (text, "label")
