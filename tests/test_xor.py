from decryptre import xor

MESSAGE = (
    "This is a reasonably long message so that the repeating key attack has "
    "enough data to find the key length and recover every byte of the key."
)


def test_roundtrip_with_text_key():
    encrypted = xor.xor_encrypt("hello", "k")
    assert xor.xor_decrypt(xor.from_bytes(encrypted), "k") == "hello"


def test_roundtrip_preserves_bytes():
    raw = bytes(range(256))
    assert xor.xor_bytes(raw, b"key") != raw
    assert xor.xor_bytes(xor.xor_bytes(raw, b"key"), b"key") == raw


def test_empty_key_rejected():
    try:
        xor.xor_bytes(b"abc", b"")
    except ValueError:
        pass
    else:  # pragma: no cover - the assertion below explains the failure
        raise AssertionError("empty XOR key should raise ValueError")


def test_index_of_coincidence_english_vs_random():
    english = xor.to_bytes(MESSAGE)
    assert xor.index_of_coincidence(english) > 0.055


def test_break_single_byte_recovers_key():
    encrypted = xor.xor_encrypt(MESSAGE, b"\x42")
    best = xor.break_single_byte(encrypted, top=1)[0]
    assert best.params["key"] == 0x42
    assert best.text == MESSAGE


def test_break_repeating_key_recovers_key():
    encrypted = xor.xor_encrypt(MESSAGE, b"key")
    best = xor.break_repeating_key(encrypted, max_key_length=8, top=1)[0]
    assert bytes.fromhex(best.params["key"]) == b"key"
    assert best.text == MESSAGE


def test_break_xor_merges_attacks():
    encrypted = xor.xor_encrypt(MESSAGE, b"\x13")
    results = xor.break_xor(encrypted, max_key_length=8, top=3)
    assert results
    assert any(candidate.text == MESSAGE for candidate in results)
