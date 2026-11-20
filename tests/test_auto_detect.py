import base64

from decryptre import auto_detect, classical, encodings, xor

MESSAGE = "This is a secret message for the layered detection test."
CAESAR = classical.caesar_encrypt(MESSAGE, 7)


def test_detects_single_caesar_layer():
    results = auto_detect.detect(CAESAR, max_depth=2, top=3)
    assert any(candidate.text == MESSAGE for candidate in results)


def test_detects_base64_then_caesar():
    layered = encodings.encode_base64(CAESAR)
    results = auto_detect.detect(layered, max_depth=3, top=3)
    assert results[0].text == MESSAGE


def test_detects_double_base64_cycle_safely():
    nested = encodings.encode_base64(encodings.encode_base64(MESSAGE))
    results = auto_detect.detect(nested, max_depth=5, top=3)
    assert any(candidate.text == MESSAGE for candidate in results)


def test_detects_hex_encoded_xor():
    encrypted = xor.xor_encrypt(MESSAGE, b"\x5a")
    layered = encrypted.hex()
    results = auto_detect.detect(layered, max_depth=3, top=5)
    assert any(candidate.text == MESSAGE for candidate in results)


def test_unwraps_xor_cli_format():
    token = base64.urlsafe_b64encode(xor.xor_encrypt(MESSAGE, b"k")).decode("ascii")
    results = auto_detect.detect(auto_detect.XOR_PREFIX + token.rstrip("="), max_depth=2, top=3)
    assert any(candidate.text == MESSAGE for candidate in results)


def test_candidate_budget_is_respected():
    layered = encodings.encode_base64(CAESAR)
    results = auto_detect.detect(layered, max_depth=5, max_candidates=1, top=3)
    assert results


def test_depth_limit_returns_input_when_zero():
    results = auto_detect.detect(CAESAR, max_depth=0, top=1)
    assert results[0].text == CAESAR
