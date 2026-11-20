import pytest

from decryptre import classical

MESSAGE = (
    "The quick brown fox jumps over the lazy dog. This is a test of the cipher "
    "and it should be long enough for frequency analysis to work properly."
)
AUSTEN = (
    "It was the best of times it was the worst of times it was the age of wisdom "
    "it was the age of foolishness it was the epoch of belief it was the epoch of "
    "incredulity it was the season of light it was the season of darkness it was "
    "the spring of hope it was the winter of despair we had everything before us"
)


def test_caesar_known_vector_and_roundtrip():
    assert classical.caesar_encrypt("abc", 3) == "def"
    assert classical.caesar_decrypt("def", 3) == "abc"
    assert classical.caesar_encrypt("Hello, World!", 3) == "Khoor, Zruog!"
    assert classical.rot13("attack at dawn") == "nggnpx ng qnja"


def test_break_caesar_recovers_shift():
    for shift in (1, 3, 7, 13, 25):
        encrypted = classical.caesar_encrypt(MESSAGE, shift)
        best = classical.break_caesar(encrypted, top=1)[0]
        assert best.params["shift"] == shift
        assert best.text == MESSAGE


def test_atbash_is_its_own_inverse():
    assert classical.atbash("Hello, World!") == "Svool, Dliow!"
    assert classical.atbash(classical.atbash(MESSAGE)) == MESSAGE
    assert classical.break_atbash(classical.atbash(MESSAGE))[0].text == MESSAGE


def test_vigenere_known_vector_and_roundtrip():
    assert classical.vigenere_encrypt("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"
    assert classical.vigenere_decrypt("LXFOPVEFRNHR", "LEMON") == "ATTACKATDAWN"
    with pytest.raises(ValueError):
        classical.vigenere_encrypt("abc", "123")


def test_break_vigenere_recovers_key_on_long_text():
    encrypted = classical.vigenere_encrypt(MESSAGE, "lemon")
    best = classical.break_vigenere(encrypted, max_key_length=8, top=1)[0]
    assert best.params["key"] == "lemon"
    assert best.text == MESSAGE


def test_railfence_known_vector_and_roundtrip():
    plain = "WEAREDISCOVEREDFLEEATONCE"
    assert classical.railfence_encrypt(plain, 3) == "WECRLTEERDSOEEFEAOCAIVDEN"
    assert classical.railfence_decrypt("WECRLTEERDSOEEFEAOCAIVDEN", 3) == plain
    assert classical.railfence_encrypt(MESSAGE, 1) == MESSAGE


def test_break_railfence_recovers_rails():
    encrypted = classical.railfence_encrypt(MESSAGE, 4)
    best = classical.break_railfence(encrypted, max_rails=8, top=1)[0]
    assert best.params["rails"] == 4
    assert best.text == MESSAGE


def test_substitution_roundtrip():
    key = "qwertyuiopasdfghjklzxcvbnm"
    encrypted = classical.substitution_encrypt(MESSAGE, key)
    assert encrypted != MESSAGE
    assert classical.substitution_decrypt(encrypted, key) == MESSAGE
    with pytest.raises(ValueError):
        classical.substitution_decrypt(MESSAGE, "too-short")


def test_break_substitution_on_paragraph():
    key = "qwertyuiopasdfghjklzxcvbnm"
    encrypted = classical.substitution_encrypt(AUSTEN, key)
    best = classical.break_substitution(
        encrypted, restarts=5, iterations=10000, top=1
    )[0]
    accuracy = sum(a == b for a, b in zip(best.text, AUSTEN)) / len(AUSTEN)
    assert accuracy > 0.95


def test_break_substitution_needs_enough_text():
    assert classical.break_substitution("too short") == []
