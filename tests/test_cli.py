import pytest

from decryptre.cli import main

MESSAGE = "Meet me at the old lighthouse at midnight."
CAESAR = "Tlla tl ha aol vsk spnoaovbzl ha tpkupnoa."


def run(capsys, argv):
    code = main(argv)
    captured = capsys.readouterr()
    assert code == 0
    return captured.out


def test_caesar_decrypt_with_explicit_shift(capsys):
    out = run(capsys, ["decrypt", "--input", CAESAR, "--method", "caesar", "--shift", "7"])
    assert MESSAGE in out


def test_caesar_decrypt_auto_shift(capsys):
    out = run(capsys, ["decrypt", "--input", CAESAR, "--method", "caesar"])
    assert MESSAGE in out


def test_auto_detection_prints_best_result(capsys):
    out = run(capsys, ["decrypt", "--input", "VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlLg=="])
    assert "This is a secret message." in out


def test_encode_then_decode_roundtrip(capsys):
    encoded = run(capsys, ["encrypt", "--input", MESSAGE, "--method", "base64"]).strip()
    decoded = run(capsys, ["decrypt", "--input", encoded, "--method", "base64"])
    assert MESSAGE in decoded


def test_fernet_roundtrip_via_cli(capsys):
    token = run(
        capsys,
        ["encrypt", "--input", MESSAGE, "--method", "fernet", "--key", "opensesame"],
    ).strip()
    plain = run(
        capsys,
        ["decrypt", "--input", token, "--method", "fernet", "--key", "opensesame"],
    )
    assert MESSAGE in plain


def test_xor_roundtrip_via_cli(capsys):
    token = run(
        capsys, ["encrypt", "--input", MESSAGE, "--method", "xor", "--key", "key"]
    ).strip()
    assert token.startswith("decryptre:xor:")
    plain = run(capsys, ["decrypt", "--input", token, "--method", "xor", "--key", "key"])
    assert MESSAGE in plain


def test_identify_reports_hash_and_one_way_note(capsys):
    out = run(
        capsys,
        ["identify", "--input", "5d41402abc4b2a76b9719d911017c592"],
    )
    assert "md5" in out
    assert "one-way" in out


def test_missing_key_for_vigenere_encrypt_exits():
    with pytest.raises(SystemExit) as excinfo:
        main(["encrypt", "--input", "text", "--method", "vigenere"])
    assert "key is required" in str(excinfo.value)


def test_unknown_method_exits():
    with pytest.raises(SystemExit) as excinfo:
        main(["decrypt", "--input", "text", "--method", "nonsense"])
    assert "unknown method" in str(excinfo.value)
