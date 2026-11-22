"""Tests for explicit OpenSSL dictionary/incremental process parallelism."""

import base64
from pathlib import Path

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from decryptre import incremental, openssl_compat
from decryptre.cli import main

MESSAGE = "The quick brown fox jumps over the lazy dog."


def _aes_blob(passphrase, text=MESSAGE):
    salt = b"12345678"
    key, iv = openssl_compat.evp_bytes_to_key(
        passphrase.encode(), salt, 32, 16, "md5"
    )
    body = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(text.encode(), 16))
    return base64.b64encode(b"Salted__" + salt + body).decode("ascii")


def test_parallel_dictionary_matches_serial_result():
    target = "late-target-1050"
    words = [f"nope-{index}" for index in range(1200)]
    words[1050] = target
    blob = _aes_blob(target)

    serial = openssl_compat.dictionary_attack(blob, words, top=1, workers=1)
    parallel = openssl_compat.dictionary_attack(blob, words, top=1, workers=2)

    assert serial
    assert parallel
    assert parallel[0].params["passphrase"] == target
    assert parallel[0].text == serial[0].text == MESSAGE
    assert parallel[0].verified is True


def test_parallel_incremental_finds_hit_and_saves_complete(tmp_path):
    blob = _aes_blob("042")
    prepared = openssl_compat.prepare_legacy_attempt(blob)
    state = incremental.SearchState.create(
        prepared.digest, "0123456789", 1, 3, prepared.variant_count
    )

    result = openssl_compat.parallel_incremental_attack(
        blob, state, tmp_path / "state.json", 2
    )

    assert result is not None
    assert result[0] == "042"
    assert result[1][0] == MESSAGE
    assert state.complete is True
    saved = incremental.SearchState.load(tmp_path / "state.json")
    assert saved.complete is True
    assert saved.skip == 43
    assert saved.passphrases_done == 153


def test_parallel_incremental_resumes_at_a_mid_length_position(tmp_path):
    blob = _aes_blob("042")
    prepared = openssl_compat.prepare_legacy_attempt(blob)
    state = incremental.SearchState.create(
        prepared.digest, "0123456789", 1, 3, prepared.variant_count
    )
    state.next_length = 3
    state.skip = 20
    state.passphrases_done = 10 + 100 + 20

    result = openssl_compat.parallel_incremental_attack(
        blob, state, tmp_path / "resume.json", 2
    )

    assert result is not None
    assert result[0] == "042"
    assert state.complete is True
    assert state.skip == 43
    assert state.passphrases_done == 153


def test_workers_flag_is_documented_and_validated(capsys):
    with pytest.raises(SystemExit):
        main(["decrypt", "--help"])
    assert "--workers" in capsys.readouterr().out
    with pytest.raises(SystemExit) as excinfo:
        main(["decrypt", "--input", "hello", "--workers", "0"])
    assert "at least 1" in str(excinfo.value)
    with pytest.raises(SystemExit) as excinfo:
        main(["decrypt", "--input", "hello", "--workers", "2"])
    assert "--method openssl" in str(excinfo.value)
