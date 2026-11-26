import pytest

from decryptre import modern_crypto
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


def test_identify_reports_an_authenticated_container(capsys):
    token = modern_crypto.encrypt_aes(MESSAGE, "Love", mode="gcm")

    out = run(capsys, ["identify", "--input", token])

    assert "AES-256-GCM" in out
    assert "tag proves the passphrase" in out


def test_missing_key_for_vigenere_encrypt_exits():
    with pytest.raises(SystemExit) as excinfo:
        main(["encrypt", "--input", "text", "--method", "vigenere"])
    assert "key is required" in str(excinfo.value)


def test_unknown_method_exits():
    with pytest.raises(SystemExit) as excinfo:
        main(["decrypt", "--input", "text", "--method", "nonsense"])
    assert "unknown method" in str(excinfo.value)


def test_encrypt_output_file_roundtrips_through_decrypt(tmp_path, capsys):
    target = tmp_path / "ciphertext.txt"
    code = main(
        [
            "encrypt",
            "--input",
            MESSAGE,
            "--method",
            "aes",
            "--key",
            "opensesame",
            "--iterations",
            "1000",
            "--output",
            str(target),
        ]
    )

    assert code == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    token = target.read_text(encoding="utf-8")
    assert token.endswith("\n") and token.count("\n") == 1

    plain = run(
        capsys,
        ["decrypt", "--input", str(target), "--method", "aes", "--key", "opensesame"],
    )
    assert MESSAGE in plain


def test_encrypt_output_file_is_not_wrapped_by_the_terminal(tmp_path):
    long_text = "A" * 5000
    target = tmp_path / "long.txt"

    assert main(
        [
            "encrypt",
            "--input",
            long_text,
            "--method",
            "base64",
            "--output",
            str(target),
        ]
    ) == 0

    written = target.read_text(encoding="utf-8")
    assert written == _base64(long_text) + "\n"


def _base64(text):
    import base64

    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def test_priority_flag_is_documented_and_validated(capsys):
    with pytest.raises(SystemExit):
        main(["decrypt", "--help"])
    assert "--priority" in capsys.readouterr().out

    with pytest.raises(SystemExit):
        main(["decrypt", "--input", "hello", "--priority", "nonsense"])


def test_encrypt_help_documents_output(capsys):
    with pytest.raises(SystemExit):
        main(["encrypt", "--help"])
    assert "--output" in capsys.readouterr().out


def test_mutations_default_depends_on_the_method():
    from decryptre.cli import _mutations_for, build_parser

    parser = build_parser()
    openssl = parser.parse_args(["decrypt", "--input", "x", "--method", "openssl"])
    assert _mutations_for(openssl, "openssl") == "numbers"
    assert _mutations_for(openssl, "aes") == "off"

    explicit = parser.parse_args(
        ["decrypt", "--input", "x", "--method", "aes", "--mutations", "symbols"]
    )
    assert _mutations_for(explicit, "aes") == "symbols"


def test_modern_scan_forwards_the_case_variant_prefix(monkeypatch):
    from decryptre import cli

    counts = {"small": 10_001, "medium": 1_368_353}
    seen = {}
    monkeypatch.setattr(cli.wordlists, "tier_count", lambda tier: counts[tier])
    monkeypatch.setattr(cli.wordlists, "iter_tier", lambda tier: iter([b"love"]))
    monkeypatch.setattr(
        cli.modern_crypto, "estimate_attack_seconds", lambda *args: 1.0
    )
    monkeypatch.setattr(cli.resources, "lower_priority", lambda priority: None)

    def fake_stream(text, factory, total, **kwargs):
        seen.update(total=total, kwargs=kwargs)
        return []

    monkeypatch.setattr(cli.modern_crypto, "dictionary_attack_stream", fake_stream)
    args = cli.build_parser().parse_args([
        "decrypt",
        "--input",
        "decryptre:v1:AAAA",
        "--method",
        "aes",
        "--wordlist-tier",
        "medium",
        "--workers",
        "1",
    ])

    with pytest.raises(SystemExit):
        cli._decrypt_with_method("aes", "decryptre:v1:AAAA", args)

    # The advertised total and the scanner must agree on the prefix, or the
    # ETA and progress bar describe a scan that is not the one being run.
    assert seen["kwargs"]["case_variant_prefix"] == 10_001
    assert seen["total"] == cli.wordlists.expansion_count(
        1_368_353, args.case_variants, "off", 10_001
    )
