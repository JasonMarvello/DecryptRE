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
        modern_crypto.encrypt_aes(MESSAGE, PASSPHRASE, mode="cbc"),
    ):
        assert modern_crypto.try_decrypt(token, "wrong") is None


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
