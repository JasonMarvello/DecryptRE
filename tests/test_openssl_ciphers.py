"""Blowfish-CBC / CAST5-CBC OpenSSL support and scan progress."""

import base64
import hashlib

import pytest

from decryptre import auto_detect, openssl_compat
from decryptre.cli import main

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish, CAST5
except ImportError:  # pragma: no cover - cryptography 41/42
    from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish, CAST5

from cryptography.hazmat.primitives.ciphers import Cipher, modes

MESSAGE = "The quick brown fox jumps over the lazy dog."
PASSPHRASE = "pass123"


def _cbc_blob(algorithm, text, passphrase, digest="md5", salt=b"salty123"):
    key_length = 16
    key, iv = openssl_compat.evp_bytes_to_key(
        passphrase.encode(), salt, key_length, len(salt), digest
    )
    data = text.encode("utf-8")
    padding = 8 - len(data) % 8
    data += bytes([padding]) * padding
    context = Cipher(algorithm(key), modes.CBC(iv)).encryptor()
    body = context.update(data) + context.finalize()
    return base64.b64encode(b"Salted__" + salt + body).decode("ascii")


def _pbkdf2_blob(algorithm, text, passphrase, salt=b"salty123"):
    material = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode(), salt, 10_000, 16 + len(salt)
    )
    key, iv = material[:16], material[16:]
    data = text.encode("utf-8")
    padding = 8 - len(data) % 8
    data += bytes([padding]) * padding
    context = Cipher(algorithm(key), modes.CBC(iv)).encryptor()
    body = context.update(data) + context.finalize()
    return base64.b64encode(b"Salted__" + salt + body).decode("ascii")


def test_cipher_registry_lists_new_ciphers():
    labels = openssl_compat.available_ciphers()
    assert "Blowfish-CBC" in labels
    assert "CAST5-CBC" in labels
    assert "AES-256-CBC" in labels


@pytest.mark.parametrize(
    "algorithm,label,digest",
    [
        (Blowfish, "Blowfish-CBC", "md5"),
        (Blowfish, "Blowfish-CBC", "sha256"),
        (CAST5, "CAST5-CBC", "md5"),
        (CAST5, "CAST5-CBC", "sha256"),
    ],
)
def test_roundtrip(algorithm, label, digest):
    blob = _cbc_blob(algorithm, MESSAGE, PASSPHRASE, digest)
    hit = openssl_compat.try_decrypt(blob, PASSPHRASE)
    assert hit is not None
    plain, alg = hit
    assert plain == MESSAGE
    assert label in alg
    assert openssl_compat._digest_label(digest) in alg


def test_pbkdf2_roundtrip():
    blob = _pbkdf2_blob(CAST5, MESSAGE, PASSPHRASE)
    hit = openssl_compat.try_decrypt(blob, PASSPHRASE)
    assert hit is not None
    assert hit[0] == MESSAGE
    assert "CAST5-CBC (PBKDF2-SHA-256" in hit[1]


def test_auto_opens_blowfish_with_key():
    blob = _cbc_blob(Blowfish, MESSAGE, PASSPHRASE)
    results = auto_detect.detect(blob, top=1, passphrase=PASSPHRASE)
    assert results[0].text == MESSAGE
    assert results[0].verified is True
    assert results[0].method == "openssl"
    assert "Blowfish" in results[0].params["alg"]


def test_dictionary_attack_finds_blowfish_passphrase():
    blob = _cbc_blob(Blowfish, MESSAGE, PASSPHRASE)
    results = openssl_compat.dictionary_attack(
        blob, ["wrong", "nope", PASSPHRASE], top=1
    )
    assert results
    assert results[0].text == MESSAGE
    assert results[0].params["passphrase"] == PASSPHRASE


def test_cli_reports_blowfish(capsys):
    blob = _cbc_blob(Blowfish, MESSAGE, PASSPHRASE)
    assert main(["decrypt", "--input", blob, "--method", "openssl", "--key", PASSPHRASE]) == 0
    out = capsys.readouterr().out
    assert "Blowfish-CBC" in out
    assert MESSAGE in out


def test_progress_reports_every_digest():
    calls = []
    blob = _cbc_blob(CAST5, MESSAGE, "not-in-the-list")
    words = [f"pw{index}" for index in range(40)]
    openssl_compat.dictionary_attack(
        blob, words, progress=lambda *args: calls.append(args)
    )
    assert calls[0] == (0, 40, "MD5")
    assert calls[-1] == (40, 40, "SHA-256")
    for done, total, digest in calls:
        assert 0 <= done <= total == 40
        assert digest in ("MD5", "SHA-256")
    # MD5 milestones come before SHA-256 milestones.
    first_sha = next(index for index, call in enumerate(calls) if call[2] == "SHA-256")
    assert all(call[2] == "MD5" for call in calls[:first_sha])


def test_progress_stops_at_a_hit():
    calls = []
    blob = _cbc_blob(CAST5, MESSAGE, PASSPHRASE)
    openssl_compat.dictionary_attack(
        blob,
        ["nope", PASSPHRASE, "later"],
        top=1,
        progress=lambda *args: calls.append(args),
    )
    assert calls[-1] == (2, 3, "MD5")


def test_two_result_target_keeps_scanning_after_one_hit():
    calls = []
    blob = _cbc_blob(CAST5, MESSAGE, PASSPHRASE)
    openssl_compat.dictionary_attack(
        blob,
        ["nope", PASSPHRASE, "later"],
        top=2,
        progress=lambda *args: calls.append(args),
    )
    assert calls[-1] == (3, 3, "SHA-256")


def test_cli_shows_scan_status(tmp_path, capsys):
    blob = _cbc_blob(CAST5, MESSAGE, "topsecret")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("\n".join(f"word{index}" for index in range(600)), encoding="utf-8")
    assert main(
        [
            "decrypt",
            "--input",
            blob,
            "--wordlist",
            str(wordlist),
            "--no-substitution",
            "--max-depth",
            "1",
        ]
    ) == 0
    err = capsys.readouterr().err
    assert "Trying 600 passphrases" in err
    assert "MD5: 600/600 passphrases" in err
    assert "SHA-256: 600/600 passphrases" in err


def test_cli_is_quiet_for_short_wordlists(tmp_path, capsys):
    blob = _cbc_blob(CAST5, MESSAGE, "topsecret")
    wordlist = tmp_path / "tiny.txt"
    wordlist.write_text("one\ntwo\nthree\n", encoding="utf-8")
    main(
        [
            "decrypt",
            "--input",
            blob,
            "--wordlist",
            str(wordlist),
            "--no-substitution",
            "--max-depth",
            "1",
        ]
    )
    assert "Trying" not in capsys.readouterr().err
