"""CLI semantics for --wordlist-tier."""

import base64

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from decryptre import modern_crypto, openssl_compat, wordlist
from decryptre.cli import main
from decryptre.models import Candidate

MESSAGE = "tier test plaintext"


def _blob(passphrase="alpha"):
    salt = b"12345678"
    key, iv = openssl_compat.evp_bytes_to_key(
        passphrase.encode(), salt, 32, 16, "md5"
    )
    body = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(MESSAGE.encode(), 16))
    return base64.b64encode(b"Salted__" + salt + body).decode("ascii")


@pytest.mark.parametrize(
    "argv, message",
    [
        (
            ["--input", "x", "--method", "auto", "--wordlist-tier", "small"],
            "only applies to --method openssl",
        ),
        (
            [
                "--input",
                "x",
                "--method",
                "openssl",
                "--wordlist",
                "words.txt",
                "--wordlist-tier",
                "small",
            ],
            "mutually exclusive",
        ),
        (
            [
                "--input",
                "x",
                "--method",
                "openssl",
                "--wordlist-tier",
                "small",
                "--key",
                "alpha",
            ],
            "cannot be combined with --key",
        ),
        (
            [
                "--input",
                "x",
                "--method",
                "openssl",
                "--wordlist-tier",
                "small",
                "--incremental",
            ],
            "cannot be combined with --incremental",
        ),
        (
            [
                "--input",
                "x",
                "--method",
                "openssl",
                "--wordlist-tier",
                "small",
                "--no-wordlist",
            ],
            "cannot be combined with --no-wordlist",
        ),
    ],
)
def test_tier_validation(argv, message):
    with pytest.raises(SystemExit) as excinfo:
        main(["decrypt", *argv])
    assert message in str(excinfo.value)


@pytest.mark.parametrize(
    "tier, expected",
    [
        ("small", 10_001),
        ("medium", 1_368_353),
        ("5m", 5_000_000),
        ("10m", 10_000_000),
        ("50m", 50_000_000),
        ("100m", 100_000_000),
    ],
)
def test_explicit_openssl_uses_requested_tier(
    monkeypatch, capsys, tier, expected
):
    seen = {}

    def fake_stream(token, factory, total, **kwargs):
        seen["total"] = total
        return [
            Candidate(
                MESSAGE,
                "openssl",
                {"alg": "test", "passphrase": "alpha"},
                1.0,
                verified=True,
            )
        ]

    monkeypatch.setattr(
        "decryptre.cli.openssl_compat.dictionary_attack_stream", fake_stream
    )
    code = main(
        [
            "decrypt",
            "--input",
            _blob(),
            "--method",
            "openssl",
            "--wordlist-tier",
            tier,
            "--case-variants",
            "off",
            "--mutations",
            "off",
            "--workers",
            "1",
        ]
    )
    assert code == 0
    assert seen["total"] == expected
    assert MESSAGE in capsys.readouterr().out


def test_explicit_openssl_defaults_to_medium(monkeypatch):
    seen = {}

    def fake_stream(token, factory, total, **kwargs):
        seen["total"] = total
        return [
            Candidate(
                MESSAGE,
                "openssl",
                {"alg": "test", "passphrase": "alpha"},
                1.0,
                verified=True,
            )
        ]

    monkeypatch.setattr(
        "decryptre.cli.openssl_compat.dictionary_attack_stream", fake_stream
    )
    assert (
        main(
            [
                "decrypt",
                "--input",
                _blob(),
                "--method",
                "openssl",
                "--case-variants",
                "off",
                "--mutations",
                "off",
                "--workers",
                "1",
            ]
        )
        == 0
    )
    assert seen["total"] == wordlist.tier_count("medium")


def test_missing_large_tier_explains_local_build(monkeypatch, tmp_path):
    monkeypatch.setattr(
        wordlist, "ROCKYOU_META_PATH", tmp_path / "rockyou-large.json"
    )
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "decrypt",
                "--input",
                _blob(),
                "--method",
                "openssl",
                "--wordlist-tier",
                "large",
                "--workers",
                "1",
            ]
        )
    assert "not shipped" in str(excinfo.value)


def test_modern_container_accepts_a_wordlist_tier(monkeypatch, capsys):
    token = modern_crypto.encrypt_aes(MESSAGE, "Love", mode="gcm")
    seen = {}

    def fake_stream(text, factory, total, **kwargs):
        seen.update(total=total, kwargs=kwargs, words=list(factory())[:2])
        return [
            Candidate(
                MESSAGE,
                "modern",
                {"alg": "aes-gcm", "passphrase": "Love"},
                1.0,
                verified=True,
            )
        ]

    monkeypatch.setattr(
        "decryptre.cli.modern_crypto.dictionary_attack_stream", fake_stream
    )

    code = main(
        [
            "decrypt",
            "--input",
            token,
            "--method",
            "aes",
            "--wordlist-tier",
            "small",
            "--workers",
            "2",
        ]
    )

    assert code == 0
    assert seen["total"] == wordlist.case_variant_count(
        wordlist.tier_count("small"), "common"
    )
    assert seen["words"] == [b"password", b"123456"]
    assert seen["kwargs"]["workers"] == 2
    assert seen["kwargs"]["case_variants"] == "common"
    assert seen["kwargs"]["mutations"] == "off"
    assert "--mutations numbers|symbols|common|all" in capsys.readouterr().err


def test_modern_failure_names_the_tier_it_searched(monkeypatch):
    token = modern_crypto.encrypt_aes(MESSAGE, "Love", mode="gcm")
    monkeypatch.setattr(
        "decryptre.cli.modern_crypto.dictionary_attack_stream",
        lambda *args, **kwargs: [],
    )

    with pytest.raises(SystemExit) as excinfo:
        main(
            ["decrypt", "--input", token, "--method", "aes", "--workers", "1"]
        )

    message = str(excinfo.value)
    assert "small tier" in message
    assert "10,001 base candidates" in message


def test_case_variants_all_warns_on_generated_tiers(monkeypatch, capsys):
    def fake_stream(token, factory, total, **kwargs):
        return [
            Candidate(
                MESSAGE,
                "openssl",
                {"alg": "test", "passphrase": "alpha"},
                1.0,
                verified=True,
            )
        ]

    monkeypatch.setattr(
        "decryptre.cli.openssl_compat.dictionary_attack_stream", fake_stream
    )

    assert (
        main(
            [
                "decrypt",
                "--input",
                _blob(),
                "--method",
                "openssl",
                "--wordlist-tier",
                "50m",
                "--case-variants",
                "all",
                "--workers",
                "1",
            ]
        )
        == 0
    )
    assert "much longer than a plain list scan" in capsys.readouterr().err


def _write_words(tmp_path, *words):
    path = tmp_path / "words.txt"
    path.write_text("\n".join(words) + "\n", encoding="utf-8")
    return str(path)


def test_openssl_tries_number_tails_by_default(tmp_path):
    code = main(
        [
            "decrypt",
            "--input",
            _blob("alpha1"),
            "--method",
            "openssl",
            "--wordlist",
            _write_words(tmp_path, "alpha"),
            "--workers",
            "1",
        ]
    )

    assert code == 0


def test_mutations_off_keeps_the_list_as_written(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "decrypt",
                "--input",
                _blob("alpha1"),
                "--method",
                "openssl",
                "--wordlist",
                _write_words(tmp_path, "alpha"),
                "--mutations",
                "off",
                "--workers",
                "1",
            ]
        )

    assert "No passphrase" in str(excinfo.value)


def test_symbol_tails_are_opt_in(tmp_path):
    words = _write_words(tmp_path, "love")
    blob = _blob("Love!")

    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "decrypt",
                "--input",
                blob,
                "--method",
                "openssl",
                "--wordlist",
                words,
                "--workers",
                "1",
            ]
        )
    assert "No passphrase" in str(excinfo.value)

    assert (
        main(
            [
                "decrypt",
                "--input",
                blob,
                "--method",
                "openssl",
                "--wordlist",
                words,
                "--mutations",
                "symbols",
                "--workers",
                "1",
            ]
        )
        == 0
    )
