"""CLI semantics for --wordlist-tier."""

import base64

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from decryptre import openssl_compat, wordlist
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
    [("small", 10_001), ("medium", 1_368_353)],
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
