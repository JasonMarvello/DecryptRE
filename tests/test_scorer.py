from decryptre.scorer import (
    bigram_score,
    chi_square,
    printable_ratio,
    score_text,
    vowel_word_ratio,
)

ENGLISH = (
    "The quick brown fox jumps over the lazy dog. This is an ordinary English "
    "sentence with common words, and it should score better than noise."
)
ROT13 = (
    "Gur dhvpx oebja sbk whzcf bire gur ynml qbt. Guvf vf na beqvanel Ratyvfu "
    "fragrapr jvgu pbzzba jbeqf, naq vg fubhyq fpber orggre guna abvfr."
)
GIBBERISH = "xqzt vbnm klop wrty sdfg hjkl qwrt zxcv bnml poiu ytre"


def test_english_beats_rot13_and_gibberish():
    assert score_text(ENGLISH) > score_text(ROT13)
    assert score_text(ENGLISH) > score_text(GIBBERISH)


def test_english_chi_square_is_low():
    assert chi_square(ENGLISH) < chi_square("qzxj vvkk qqzz jjxx")


def test_bigram_score_prefers_english():
    assert bigram_score(ENGLISH) > bigram_score("xkcd qzwv jjkk vvxx")


def test_printable_ratio():
    assert printable_ratio("hello") == 1.0
    assert printable_ratio("he\x00llo") < 1.0
    assert printable_ratio("") == 0.0


def test_vowel_word_ratio_flags_consonant_soup():
    assert vowel_word_ratio("the quick brown fox") == 0.0
    assert vowel_word_ratio("xqzt vbnm klp") == 1.0


def test_binary_scores_badly():
    assert score_text("\x00\x01\x02\xff" * 20) < -100
