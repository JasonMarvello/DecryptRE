"""End-to-end matrix: encrypt with every method, recover through `decrypt --method auto`.

Each case is its own test so a failure names the method instead of hiding in a
single summary. The sample is ordinary English prose (not a pangram) because
the scorer models English letter and word frequencies.
"""

import base64
import subprocess
import sys

import pytest

SAMPLE = (
    "Alice was beginning to get very tired of sitting by her sister on the bank, "
    "and of having nothing to do. She had peeped into the book her sister was "
    "reading, but it had no pictures or conversations in it, and what is the use "
    "of a book without pictures or conversations? So she was considering in her "
    "own mind, as well as she could, for the hot day made her feel very sleepy "
    "and stupid, whether the pleasure of making a daisy chain would be worth the "
    "trouble of getting up and picking the daisies."
)
PASSPHRASE = "correct horse"
SUBSTITUTION_KEY = "qwertyuiopasdfghjklzxcvbnm"
FAST_KDF = ("--iterations", "1000")


def cli(*arguments):
    proc = subprocess.run(
        [sys.executable, "-m", "decryptre", *arguments],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def encrypt(method, text=SAMPLE, key=None, extra=()):
    arguments = ["encrypt", "--input", text, "--method", method]
    if key:
        arguments += ["--key", key]
    arguments += list(extra)
    return cli(*arguments).strip()


def decrypt_auto(token, key=None, extra=()):
    arguments = ["decrypt", "--input", token, "--method", "auto", "--top", "10"]
    if key:
        arguments += ["--key", key]
    arguments += list(extra)
    return cli(*arguments)


# ---------------------------------------------------------------------------
# Single layer: every supported method
# ---------------------------------------------------------------------------

SINGLE_LAYER = [
    ("base64", None, ()),
    ("base32", None, ()),
    ("base16", None, ()),
    ("url", None, ()),
    ("ascii85", None, ()),
    ("caesar", None, ("--shift", "7")),
    ("atbash", None, ()),
    ("vigenere", "lantern", ()),
    ("railfence", None, ("--rails", "5")),
    ("substitution", SUBSTITUTION_KEY, ()),
    ("xor", "k3y", ()),
    ("fernet", PASSPHRASE, FAST_KDF),
    ("aes-gcm", PASSPHRASE, FAST_KDF),
    ("aes-cbc", PASSPHRASE, FAST_KDF + ("--aes-mode", "cbc")),
    ("des3", PASSPHRASE, FAST_KDF),
]


@pytest.mark.parametrize(
    "method,key,extra", SINGLE_LAYER, ids=[row[0] for row in SINGLE_LAYER]
)
def test_single_layer_auto_recovery(method, key, extra):
    token = encrypt(method, key=key, extra=extra)
    # Substitution needs its solver enabled; everything else can skip it.
    decrypt_extra = () if method == "substitution" else ("--no-substitution",)
    output = decrypt_auto(token, key=key, extra=decrypt_extra)
    assert SAMPLE in output, f"{method} was not recovered by auto mode"


# ---------------------------------------------------------------------------
# Stacked layers: auto must unwrap the outer encoding first
# ---------------------------------------------------------------------------

def test_aes_then_base64():
    token = encrypt("aes", key=PASSPHRASE, extra=FAST_KDF)
    wrapped = base64.b64encode(token.encode("ascii")).decode("ascii")
    output = decrypt_auto(wrapped, key=PASSPHRASE)
    assert SAMPLE in output


def test_fernet_then_hex():
    token = encrypt("fernet", key=PASSPHRASE, extra=FAST_KDF)
    wrapped = token.encode("ascii").hex()
    output = decrypt_auto(wrapped, key=PASSPHRASE)
    assert SAMPLE in output


def test_des3_then_base32():
    token = encrypt("des3", key=PASSPHRASE, extra=FAST_KDF)
    wrapped = base64.b32encode(token.encode("ascii")).decode("ascii")
    output = decrypt_auto(wrapped, key=PASSPHRASE)
    assert SAMPLE in output


def test_xor_then_hex():
    token = encrypt("xor", key="k3y")
    wrapped = token.encode("ascii").hex()
    output = decrypt_auto(wrapped, extra=("--no-substitution",))
    assert SAMPLE in output


def test_xor_then_base64():
    token = encrypt("xor", key="k3y")
    wrapped = base64.b64encode(token.encode("ascii")).decode("ascii")
    output = decrypt_auto(wrapped, extra=("--no-substitution",))
    assert SAMPLE in output


def test_caesar_then_base64():
    token = encrypt("caesar", extra=("--shift", "7"))
    wrapped = base64.b64encode(token.encode("utf-8")).decode("ascii")
    output = decrypt_auto(wrapped, extra=("--no-substitution",))
    assert SAMPLE in output


def test_vigenere_then_base64():
    token = encrypt("vigenere", key="lantern")
    wrapped = base64.b64encode(token.encode("utf-8")).decode("ascii")
    output = decrypt_auto(wrapped, extra=("--no-substitution",))
    assert SAMPLE in output


def test_aes_then_base64_then_hex():
    token = encrypt("aes", key=PASSPHRASE, extra=FAST_KDF)
    once = base64.b64encode(token.encode("ascii")).decode("ascii")
    twice = once.encode("ascii").hex()
    output = decrypt_auto(twice, key=PASSPHRASE)
    assert SAMPLE in output
