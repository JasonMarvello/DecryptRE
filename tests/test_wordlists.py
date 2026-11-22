"""The bundled passphrase lists and the auto/explicit split."""

from decryptre.cli import load_common_wordlist, load_wordlist


def test_common_wordlist_is_still_the_short_fast_list():
    assert len(load_common_wordlist()) == 10001


def test_bundled_dictionary_is_multilingual():
    words = set(load_wordlist())

    assert len(words) > 1_000_000
    # English (US and UK spellings), Indonesian, Hindi, Russian, Ukrainian.
    for word in (
        "password",
        "colour",
        "organise",
        "halo",
        "abad",
        "नमस्ते",
        "привет",
        "привіт",
    ):
        assert word in words


def test_custom_wordlist_replaces_the_bundled_lists(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("# comment\none\n\ntwo\n", encoding="utf-8")

    assert load_wordlist(str(path)) == ["one", "two"]
