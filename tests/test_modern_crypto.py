import base64

import pytest

from decryptre import modern_crypto
from decryptre.containers import MAGIC, ContainerError, is_container, pack, unpack

MESSAGE = "Attack at dawn. This message is protected with a passphrase."
PASSPHRASE = "hunter2"


def test_container_roundtrip():
    token = pack({"v": 1, "alg": "fernet", "token": "abc"})
    assert token.startswith(MAGIC)
    assert is_container(token)
    assert unpack(token)["alg"] == "fernet"
    with pytest.raises(ContainerError):
        unpack("not a container")


def test_fernet_roundtrip():
    token = modern_crypto.encrypt_fernet(MESSAGE, PASSPHRASE)
    assert is_container(token)
    assert modern_crypto.decrypt_fernet(token, PASSPHRASE) == MESSAGE


@pytest.mark.parametrize("mode", ["gcm", "cbc"])
def test_aes_roundtrip(mode):
    token = modern_crypto.encrypt_aes(MESSAGE, PASSPHRASE, mode=mode)
    assert is_container(token)
    assert modern_crypto.decrypt_aes(token, PASSPHRASE) == MESSAGE


def test_scrypt_kdf_roundtrip():
    token = modern_crypto.encrypt_aes(MESSAGE, PASSPHRASE, mode="gcm", kdf="scrypt")
    assert unpack(token)["kdf"] == "scrypt"
    assert modern_crypto.decrypt_aes(token, PASSPHRASE) == MESSAGE


def test_wrong_passphrase_returns_none():
    for token in (
        modern_crypto.encrypt_fernet(MESSAGE, PASSPHRASE),
        modern_crypto.encrypt_aes(MESSAGE, PASSPHRASE, mode="gcm"),
    ):
        assert modern_crypto.try_decrypt(token, "wrong") is None


def test_wrong_passphrase_never_returns_the_message_in_cbc():
    # CBC has no authentication tag, so a wrong key passes padding about once
    # in 256 tries. It must never produce the original plaintext, and the
    # dictionary attack must not report it as verified for a random key.
    token = modern_crypto.encrypt_aes(MESSAGE, PASSPHRASE, mode="cbc")
    assert modern_crypto.try_decrypt(token, "wrong") != MESSAGE


def test_tampered_ciphertext_is_rejected():
    token = modern_crypto.encrypt_aes(MESSAGE, PASSPHRASE, mode="gcm")
    payload = unpack(token)
    raw = bytearray(base64.b64decode(payload["ciphertext"]))
    raw[0] ^= 0x01
    payload["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(ValueError):
        modern_crypto.decrypt_aes(pack(payload), PASSPHRASE)


def test_dictionary_attack_finds_passphrase():
    token = modern_crypto.encrypt_fernet(MESSAGE, PASSPHRASE)
    results = modern_crypto.dictionary_attack(token, ["nope", PASSPHRASE], top=2)
    assert results
    assert results[0].text == MESSAGE
    assert results[0].params["passphrase"] == PASSPHRASE


def test_dictionary_attack_without_container_returns_empty():
    assert modern_crypto.dictionary_attack("plain text", ["a", "b"]) == []


def test_identify_hash_shapes():
    md5 = modern_crypto.hash_digest("x", "md5")
    assert any("md5" in match for match in modern_crypto.identify_hash(md5))
    assert any(
        "sha256" in match
        for match in modern_crypto.identify_hash(modern_crypto.hash_digest("x", "sha256"))
    )
    assert any(
        "sha512" in match
        for match in modern_crypto.identify_hash(modern_crypto.hash_digest("x", "sha512"))
    )
    assert modern_crypto.identify_hash("not hex at all") == []


def test_unknown_algorithm_rejected():
    token = pack({"v": 1, "alg": "rot13"})
    with pytest.raises(ContainerError):
        modern_crypto.decrypt_modern(token, PASSPHRASE)


@pytest.mark.parametrize("kdf", ["pbkdf2", "scrypt"])
def test_des3_roundtrip(kdf):
    token = modern_crypto.encrypt_des3(MESSAGE, PASSPHRASE, kdf=kdf)
    assert is_container(token)
    assert unpack(token)["alg"] == "des3-cbc"
    assert modern_crypto.decrypt_des3(token, PASSPHRASE) == MESSAGE


def test_des3_wrong_passphrase_never_returns_the_message():
    # 3DES-CBC is unauthenticated; a wrong key can pass the padding check.
    token = modern_crypto.encrypt_des3(MESSAGE, PASSPHRASE)
    assert modern_crypto.try_decrypt(token, "wrong") != MESSAGE


def test_des3_dictionary_attack():
    token = modern_crypto.encrypt_des3(MESSAGE, PASSPHRASE)
    results = modern_crypto.dictionary_attack(token, ["nope", PASSPHRASE], top=2)
    assert results
    assert results[0].text == MESSAGE
    assert results[0].verified is True
    assert results[0].params["alg"] == "des3-cbc"


def test_des3_empty_plaintext():
    token = modern_crypto.encrypt_des3("", PASSPHRASE)
    assert modern_crypto.decrypt_des3(token, PASSPHRASE) == ""


def test_try_decrypt_any_reports_algorithm():
    token = modern_crypto.encrypt_des3(MESSAGE, PASSPHRASE)
    plain, alg = modern_crypto.try_decrypt_any(token, PASSPHRASE)
    assert plain == MESSAGE
    assert alg == "des3-cbc"


def test_aes_gcm_dictionary_attack_finds_capitalised_passphrase():
    token = modern_crypto.encrypt_aes(MESSAGE, "Love", mode="gcm")

    results = modern_crypto.dictionary_attack(token, ["love", "Love"], top=2)

    assert results
    assert results[0].params["passphrase"] == "Love"
    assert results[0].params["alg"] == "aes-gcm"
    assert results[0].verified is True


def test_case_variants_expand_a_lowercase_only_list():
    token = modern_crypto.encrypt_aes(MESSAGE, "Love", mode="gcm")

    expanded = modern_crypto.dictionary_attack(
        token, ["love"], case_variants="common"
    )

    assert expanded
    assert expanded[0].params["passphrase"] == "Love"
    assert modern_crypto.dictionary_attack(token, ["love"], case_variants="off") == []


def test_streamed_attack_calls_the_factory_once_and_reports_progress():
    token = modern_crypto.encrypt_aes(MESSAGE, "Love", mode="gcm")
    calls = []
    progress = []

    def factory():
        calls.append(1)
        return iter([b"wrong", b"Love"])

    results = modern_crypto.dictionary_attack_stream(
        token,
        factory,
        2,
        top=1,
        progress=lambda done, total, label: progress.append((done, total, label)),
    )

    assert results[0].params["passphrase"] == "Love"
    assert len(calls) == 1
    assert progress[-1][:2] == (2, 2)


def test_parallel_modern_scan_matches_the_serial_result(monkeypatch):
    token = modern_crypto.encrypt_aes(MESSAGE, "Love", mode="gcm")
    words = ["wrong", "nope", "Love"]

    serial = modern_crypto.dictionary_attack(token, words, workers=1)
    monkeypatch.setattr(modern_crypto, "PARALLEL_MIN_PASSPHRASES", 1)
    parallel = modern_crypto.dictionary_attack(token, words, workers=2)

    assert [item.params["passphrase"] for item in parallel] == [
        item.params["passphrase"] for item in serial
    ]


def test_mutations_find_a_numbered_and_symbol_passphrase():
    token = modern_crypto.encrypt_aes(MESSAGE, "Love123!", mode="gcm")

    found = modern_crypto.dictionary_attack(token, ["Love"], mutations="common")

    assert found
    assert found[0].params["passphrase"] == "Love123!"
    assert modern_crypto.dictionary_attack(token, ["Love"], mutations="off") == []


def test_parallel_mutation_scan_matches_the_serial_result(monkeypatch):
    token = modern_crypto.encrypt_aes(MESSAGE, "Love!", mode="gcm")

    serial = modern_crypto.dictionary_attack(token, ["Love"], mutations="symbols")

    monkeypatch.setattr(modern_crypto, "PARALLEL_MIN_PASSPHRASES", 1)
    parallel = modern_crypto.dictionary_attack(
        token, ["Love"], mutations="symbols", workers=2
    )

    assert serial
    assert [item.params["passphrase"] for item in parallel] == [
        item.params["passphrase"] for item in serial
    ]


def test_stream_honours_the_case_variant_prefix(monkeypatch):
    from decryptre import wordlist

    token = modern_crypto.encrypt_aes(MESSAGE, "Love", mode="gcm")
    words = [f"word{index:03d}".encode("ascii") for index in range(200)]
    attempted = []
    monkeypatch.setattr(
        modern_crypto,
        "try_decrypt",
        lambda text, passphrase: attempted.append(passphrase),
    )

    total = wordlist.expansion_count(200, "common", "numbers", 5)
    modern_crypto.dictionary_attack_stream(
        token,
        lambda: iter(words),
        total,
        top=1,
        case_variants="common",
        case_variant_prefix=5,
        mutations="numbers",
    )

    # Only the five candidates inside the prefix are expanded, so the stream
    # stops exactly at the advertised count instead of expanding all 200.
    assert total == 360
    assert len(attempted) == total
    assert {"word000", "Word000", "WORD000", "word199"} <= set(attempted)
    assert "Word199" not in attempted
