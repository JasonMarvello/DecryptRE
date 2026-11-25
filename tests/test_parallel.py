"""Tests for explicit OpenSSL dictionary/incremental process parallelism."""

import base64
from pathlib import Path

import pytest
from Crypto.Cipher import AES, DES3
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


def test_streaming_parallel_scans_and_reopens_for_both_digests():
    calls = []

    def factory():
        calls.append(True)
        return (f"nope-{index}" for index in range(1200))

    blob = _aes_blob("not-in-the-list")
    result = openssl_compat.dictionary_attack_stream(
        blob, factory, 1200, workers=2
    )

    assert result == []
    # AES-first MD5 and SHA-256 passes, then the all-cipher MD5 and SHA-256
    # passes. The list is shorter than the AES-first prefix, so every phase
    # covers all of it.
    assert len(calls) == 4


def test_streaming_keeps_non_utf8_passphrase_bytes():
    password = b"\xffsecret"
    salt = b"12345678"
    key, iv = openssl_compat.evp_bytes_to_key(password, salt, 32, 16, "md5")
    body = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(MESSAGE.encode(), 16))
    blob = base64.b64encode(b"Salted__" + salt + body).decode("ascii")

    result = openssl_compat.dictionary_attack_stream(
        blob, lambda: iter([password]), 1, workers=1
    )

    assert result
    assert result[0].text == MESSAGE
    assert result[0].params["passphrase"] == "\ufffdsecret"


def test_two_plausible_matches_are_collected(monkeypatch):
    salt = b"12345678"
    body = b"\x00" * 16
    blob = base64.b64encode(b"Salted__" + salt + body).decode("ascii")
    passwords = (b"alpha", b"beta")
    keys = {}
    for password in passwords:
        key, _iv = openssl_compat.evp_bytes_to_key(
            password, salt, 32, 16, "md5"
        )
        keys[key] = password

    def fake_decrypt(body, key, iv, label, spec):
        password = keys.get(key)
        if password is None:
            return None
        return (
            f"The secret message for {password.decode()} is readable.",
            "OpenSSL test",
        )

    monkeypatch.setattr(openssl_compat, "_decrypt_with", fake_decrypt)
    results = openssl_compat.dictionary_attack_stream(
        blob,
        lambda: iter(passwords),
        len(passwords),
        top=2,
        workers=1,
    )

    assert {item.params["passphrase"] for item in results} == {"alpha", "beta"}
    assert all(item.verified for item in results)


def test_parallel_worker_returns_every_plausible_hit_in_a_chunk(monkeypatch):
    class FakeAttempt:
        ciphers = ()
        aes_ciphers = ()

        def try_digest(self, password, digest, ciphers=None):
            if password in (b"alpha", b"beta"):
                return (
                    f"A readable secret message from {password.decode()}.",
                    "OpenSSL test",
                )
            return None

    monkeypatch.setattr(openssl_compat, "_WORKER_ATTEMPT", FakeAttempt())
    _chunk, processed, hits = openssl_compat._dictionary_parallel_worker(
        ("md5", 0, [b"alpha", b"nope", b"beta"], False)
    )

    assert processed == 3
    assert {item.params["passphrase"] for item in hits} == {"alpha", "beta"}


def test_gibberish_padding_hit_is_not_returned(monkeypatch):
    salt = b"12345678"
    body = b"\x00" * 16
    blob = base64.b64encode(b"Salted__" + salt + body).decode("ascii")
    key, _iv = openssl_compat.evp_bytes_to_key(b"alpha", salt, 32, 16, "md5")

    def fake_decrypt(body, candidate_key, iv, label, spec):
        if candidate_key == key:
            return ("xJ9$vQ2!", "OpenSSL test")
        return None

    monkeypatch.setattr(openssl_compat, "_decrypt_with", fake_decrypt)
    assert openssl_compat.dictionary_attack_stream(
        blob, lambda: iter([b"alpha"]), 1, top=2, workers=1
    ) == []


def test_chunking_is_bounded_and_preserves_order():
    chunks = list(
        openssl_compat._iter_chunks(
            (str(index) for index in range(11)), size=4
        )
    )
    assert [len(chunk) for chunk in chunks] == [4, 4, 3]
    assert chunks[0][0] == b"0"
    assert chunks[-1][-1] == b"10"


def test_worker_initializers_apply_the_requested_priority(monkeypatch):
    seen = []
    monkeypatch.setattr(
        openssl_compat, "lower_priority", lambda mode: seen.append(mode) or True
    )
    monkeypatch.setattr(
        openssl_compat, "prepare_legacy_attempt", lambda text: "attempt"
    )

    try:
        openssl_compat._dictionary_worker_init("blob", "normal")
        openssl_compat._parallel_worker_init("blob", object(), "background")
    finally:
        openssl_compat._WORKER_ATTEMPT = None
        openssl_compat._WORKER_STOP = None

    assert seen == ["normal", "background"]


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


def test_scan_phases_put_aes_first_over_the_common_prefix():
    blob = _aes_blob("whatever")
    attempt = openssl_compat.prepare_legacy_attempt(blob)

    phases = list(openssl_compat._scan_phases(attempt, 5_000_000))

    assert [digest for digest, _label, _ciphers, _limit in phases] == [
        "md5",
        "sha256",
        "md5",
        "sha256",
    ]
    assert all(
        spec.label.startswith("AES-") for spec in phases[0][2]
    )
    assert phases[0][3] == phases[1][3] == openssl_compat.AES_FIRST_PREFIX
    assert phases[2][2] is None and phases[3][2] is None
    assert phases[2][3] == phases[3][3] == 5_000_000


def test_scan_phases_cover_a_list_shorter_than_the_prefix():
    attempt = openssl_compat.prepare_legacy_attempt(_aes_blob("whatever"))

    phases = list(openssl_compat._scan_phases(attempt, 1200))

    assert [limit for _digest, _label, _ciphers, limit in phases] == [
        1200,
        1200,
        1200,
        1200,
    ]


def test_legacy_cipher_hits_are_still_found_after_the_aes_pass():
    target = "legacy-target"
    words = [f"nope-{index}" for index in range(1200)]
    words[1100] = target
    salt = b"12345678"
    key, iv = openssl_compat.evp_bytes_to_key(
        target.encode(), salt, 24, 8, "md5"
    )
    body = DES3.new(key, DES3.MODE_CBC, iv).encrypt(
        pad(MESSAGE.encode(), 8)
    )
    blob = base64.b64encode(b"Salted__" + salt + body).decode("ascii")

    results = openssl_compat.dictionary_attack_stream(
        blob, lambda: iter(words), len(words), top=1, workers=2
    )

    assert results
    assert results[0].text == MESSAGE
    assert results[0].params["passphrase"] == target


def test_priority_is_passed_into_a_streaming_scan(monkeypatch):
    seen = {}

    def fake_stream(text, factory, total, **kwargs):
        seen.update(kwargs)
        return []

    monkeypatch.setattr(openssl_compat, "dictionary_attack_stream", fake_stream)

    openssl_compat.dictionary_attack(
        _aes_blob("whatever"), [b"alpha"], priority="normal"
    )

    assert seen["priority"] == "normal"
