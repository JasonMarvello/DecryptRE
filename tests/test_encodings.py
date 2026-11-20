import pytest

from decryptre import encodings


@pytest.mark.parametrize("name", sorted(encodings.ENCODINGS))
@pytest.mark.parametrize(
    "text",
    [
        "Hello, World!",
        "line one\nline two",
        "unicode: café \u00e9\u00e8",
        "1234567890",
    ],
)
def test_roundtrip(name, text):
    assert encodings.decode(encodings.encode(text, name), name) == text


def test_known_vectors():
    assert encodings.encode("hello", "base64") == "aGVsbG8="
    assert encodings.encode("hello", "base32") == "NBSWY3DP"
    assert encodings.encode("hello", "base16") == "68656c6c6f"
    assert encodings.encode("hello world!", "url") == "hello%20world%21"
    assert encodings.encode("hello", "ascii85") == "BOu!rDZ"


def test_aliases():
    assert encodings.decode("68656c6c6f", "hex") == "hello"
    assert encodings.resolve_name("b64") == "base64"
    with pytest.raises(KeyError):
        encodings.resolve_name("not-an-encoding")


def test_base64_handles_missing_padding_and_whitespace():
    assert encodings.decode_base64("aGVs bG8") == "hello"


def test_invalid_input_raises_decode_error():
    with pytest.raises(encodings.DecodeError):
        encodings.decode_base64("not valid base64!!!")
    with pytest.raises(encodings.DecodeError):
        encodings.decode_base16("abc")
    with pytest.raises(encodings.DecodeError):
        encodings.decode_base32("!!!!")


def test_looks_like_guards_obvious_non_matches():
    assert encodings.looks_like("aGVsbG8=", "base64")
    assert not encodings.looks_like("hi", "base64")
    assert encodings.looks_like("68656c6c6f", "base16")
    assert not encodings.looks_like("hello", "url")
