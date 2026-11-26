"""The bundled passphrase tiers and streaming contract."""

import gzip
import json

import pytest

from decryptre import wordlist
from decryptre.cli import load_common_wordlist, load_wordlist


def test_common_wordlist_is_still_the_short_fast_list():
    assert len(load_common_wordlist()) == 10001


def test_bundled_dictionary_is_multilingual():
    words = set(load_wordlist())

    assert len(words) == 1_368_353
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


def test_medium_tier_is_globally_deduplicated():
    count = wordlist.tier_count("medium")
    unique = set(wordlist.iter_tier("medium"))

    assert count == 1_368_353
    assert len(unique) == count


def test_tier_stream_yields_bytes_and_preserves_non_utf8(tmp_path):
    path = tmp_path / "bytes.txt"
    path.write_bytes(b"\xffpass\n  spaced  \n# comment\n\n")

    assert list(wordlist.iter_file(path)) == [b"\xffpass", b"  spaced  "]


def test_large_tier_reports_how_to_install_it(monkeypatch, tmp_path):
    monkeypatch.setattr(
        wordlist, "ROCKYOU_META_PATH", tmp_path / "rockyou-large.json"
    )

    with pytest.raises(wordlist.WordlistError, match="not shipped"):
        wordlist.tier_count("large")
    with pytest.raises(wordlist.WordlistError, match="not shipped"):
        list(wordlist.iter_tier("large"))


def test_large_tier_streams_local_rockyou_after_medium(monkeypatch, tmp_path):
    base = tmp_path
    (base / "common.txt").write_bytes(b"alpha\nbeta\n")
    (base / "extra.txt").write_bytes(b"gamma\ndelta\n")
    with gzip.open(base / "rockyou-large.txt.gz", "wb") as handle:
        handle.write(b"delta\n#tag\nepsilon\n")
    (base / "manifest.json").write_text(
        json.dumps(
            {
                "version": 1,
                "tiers": {
                    "small": {"files": ["common.txt"], "count": 2},
                    "medium": {
                        "files": ["common.txt", "extra.txt"],
                        "count": 4,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    (base / "rockyou-large.json").write_text(
        json.dumps({"file": "rockyou-large.txt.gz", "count": 3}),
        encoding="utf-8",
    )

    monkeypatch.setattr(wordlist, "WORDLIST_DIR", base)
    monkeypatch.setattr(wordlist, "MANIFEST_PATH", base / "manifest.json")
    monkeypatch.setattr(
        wordlist, "ROCKYOU_META_PATH", base / "rockyou-large.json"
    )

    assert wordlist.tier_count("large") == 7
    assert list(wordlist.iter_tier("large")) == [
        b"alpha",
        b"beta",
        b"gamma",
        b"delta",
        b"delta",
        b"#tag",
        b"epsilon",
    ]


def test_custom_wordlist_replaces_the_bundled_lists(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("# comment\none\n\ntwo\n", encoding="utf-8")

    assert load_wordlist(str(path)) == ["one", "two"]


@pytest.mark.parametrize(
    "tier, expected",
    [
        ("5m", 5_000_000),
        ("10m", 10_000_000),
        ("50m", 50_000_000),
        ("100m", 100_000_000),
    ],
)
def test_generated_tier_counts(tier, expected):
    assert wordlist.tier_count(tier) == expected


def test_generated_tier_starts_with_the_common_list():
    stream = wordlist.iter_tier("5m")
    assert next(stream) == b"password"
    assert next(stream) == b"123456"


def test_generated_seed_variants_are_deterministic_and_unique():
    first = list(wordlist._iter_seed_variants([b"patty"], 4))
    second = list(wordlist._iter_seed_variants([b"patty"], 4))

    assert first == second
    assert first == [
        b"patty",
        b"Patty",
        b"PATTY",
        b"patty000000",
    ]


def test_names_seed_file_includes_the_requested_examples():
    names = set(wordlist.iter_file(wordlist.NAMES_PATH, comments=True))
    assert b"Patty" in names
    assert b"Verenza" in names


def test_generated_tier_has_no_packaged_files():
    with pytest.raises(wordlist.WordlistError, match="no files"):
        wordlist.tier_files("5m")


def _write_large_manifest(base):
    (base / "common.txt").write_bytes(b"alpha\n")
    (base / "manifest.json").write_text(
        json.dumps(
            {
                "version": 1,
                "tiers": {
                    "small": {"files": ["common.txt"], "count": 1},
                    "medium": {"files": ["common.txt"], "count": 1},
                },
            }
        ),
        encoding="utf-8",
    )


def test_large_tier_requires_existing_artifact(monkeypatch, tmp_path):
    base = tmp_path
    _write_large_manifest(base)
    (base / "rockyou-large.json").write_text(
        json.dumps(
            {"file": "rockyou-large.txt.gz", "count": 1, "bytes": 1}
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(wordlist, "WORDLIST_DIR", base)
    monkeypatch.setattr(wordlist, "MANIFEST_PATH", base / "manifest.json")
    monkeypatch.setattr(
        wordlist, "ROCKYOU_META_PATH", base / "rockyou-large.json"
    )

    with pytest.raises(wordlist.WordlistError, match="not shipped"):
        wordlist.tier_count("large")
    with pytest.raises(wordlist.WordlistError, match="not shipped"):
        list(wordlist.iter_tier("large"))


def test_large_tier_rejects_incomplete_artifact(monkeypatch, tmp_path):
    base = tmp_path
    _write_large_manifest(base)
    with gzip.open(base / "rockyou-large.txt.gz", "wb") as handle:
        handle.write(b"alpha\n")
    size = (base / "rockyou-large.txt.gz").stat().st_size
    (base / "rockyou-large.json").write_text(
        json.dumps(
            {
                "file": "rockyou-large.txt.gz",
                "count": 1,
                "bytes": size + 1,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(wordlist, "WORDLIST_DIR", base)
    monkeypatch.setattr(wordlist, "MANIFEST_PATH", base / "manifest.json")
    monkeypatch.setattr(
        wordlist, "ROCKYOU_META_PATH", base / "rockyou-large.json"
    )

    with pytest.raises(wordlist.WordlistError, match="incomplete"):
        wordlist.tier_count("large")


def test_corrupt_large_gzip_reports_wordlist_error(monkeypatch, tmp_path):
    base = tmp_path
    _write_large_manifest(base)
    (base / "rockyou-large.txt.gz").write_bytes(b"not a gzip file")
    (base / "rockyou-large.json").write_text(
        json.dumps({"file": "rockyou-large.txt.gz", "count": 1}),
        encoding="utf-8",
    )
    monkeypatch.setattr(wordlist, "WORDLIST_DIR", base)
    monkeypatch.setattr(wordlist, "MANIFEST_PATH", base / "manifest.json")
    monkeypatch.setattr(
        wordlist, "ROCKYOU_META_PATH", base / "rockyou-large.json"
    )

    with pytest.raises(wordlist.WordlistError, match="cannot read wordlist"):
        list(wordlist.iter_tier("large"))


def test_case_forms_add_capitalised_and_upper_only():
    assert wordlist.case_forms(b"love") == [b"love", b"Love", b"LOVE"]
    assert wordlist.case_forms(b"Love") == [b"Love", b"LOVE"]
    assert wordlist.case_forms(b"LOVE") == [b"LOVE"]
    assert wordlist.case_forms(b"123456") == [b"123456"]


def test_case_forms_leave_non_ascii_untouched():
    word = "привет".encode("utf-8")
    assert wordlist.case_forms(word) == [word]


def test_iter_case_variants_off_is_a_pass_through():
    words = [b"love", b"Love"]
    assert list(wordlist.iter_case_variants(iter(words), "off")) == words


def test_iter_case_variants_common_expands_only_the_prefix():
    expanded = list(
        wordlist.iter_case_variants(iter([b"alpha", b"beta", b"gamma"]), "common", 2)
    )

    assert expanded == [
        b"alpha",
        b"Alpha",
        b"ALPHA",
        b"beta",
        b"Beta",
        b"BETA",
        b"gamma",
    ]


def test_iter_case_variants_all_expands_enough_to_cover_generated_tiers():
    expanded = list(
        wordlist.iter_case_variants(iter([b"alpha", b"beta"]), "all", 1)
    )

    assert expanded[-3:] == [b"beta", b"Beta", b"BETA"]


def test_case_variant_count_matches_the_prefix_rule():
    assert wordlist.case_variant_count(10, "off") == 10
    assert wordlist.case_variant_count(10, "all") == 30
    assert wordlist.case_variant_count(1_368_353, "common", 10_001) == (
        1_368_353 + 20_002
    )


def test_generated_tier_tries_bare_seed_forms_first():
    assert list(wordlist._iter_seed_variants([b"patty"], 3)) == [
        b"patty",
        b"Patty",
        b"PATTY",
    ]


def test_mutation_forms_off_keeps_the_bare_candidate():
    assert wordlist.mutation_forms(b"love", "off") == [b"love"]


def test_mutation_forms_numbers_append_each_digit_after_the_bare_word():
    forms = wordlist.mutation_forms(b"love", "numbers")

    assert forms[0] == b"love"
    assert forms[1:] == [b"love" + tail for tail in wordlist._DIGIT_TAILS]
    assert len(forms) == 11


def test_mutation_forms_symbols_add_punctuation_and_digit_symbol_tails():
    forms = wordlist.mutation_forms(b"love", "symbols")

    assert b"love!" in forms
    assert b"love123!" in forms
    assert b"love12" not in forms
    assert len(set(forms)) == len(forms)


def test_mutation_forms_common_adds_runs_years_and_leading_zero_numbers():
    forms = wordlist.mutation_forms(b"love", "common")

    assert b"love123" in forms
    assert b"love007" in forms
    assert b"love1999" in forms
    assert len(forms) == 1 + wordlist.mutation_factor("common")


def test_mutation_forms_all_adds_leet_and_stays_unique():
    forms = wordlist.mutation_forms(b"love", "all")

    assert b"l0ve" in forms
    assert b"l0v3" in forms
    # "love" has two substitutable letters, so three leet forms; the factor is
    # an upper bound for words with six or more.
    assert len(forms) == 194
    assert len(forms) <= 1 + wordlist.mutation_factor("all")
    assert len(set(forms)) == len(forms)


def test_leet_forms_are_bounded_for_long_words():
    # Only the first six substitutable positions get one- and two-letter
    # substitutions, which keeps the multiplier predictable.
    forms = wordlist._leet_forms(b"assessmentsassessments")

    assert len(forms) <= wordlist._LEET_MAX_FORMS
    assert wordlist.mutation_factor("all") == 190 + wordlist._LEET_MAX_FORMS


def test_mutation_forms_leave_non_ascii_unchanged():
    word = "\u043f\u0440\u0438\u0432\u0435\u0442".encode("utf-8")

    assert wordlist.mutation_forms(word, "all") == [word]


def test_unknown_mutation_mode_is_rejected():
    with pytest.raises(wordlist.WordlistError, match="unknown mutation mode"):
        wordlist.mutation_forms(b"love", "leet")


def test_mutation_factor_counts_distinct_tails_only():
    assert wordlist.mutation_factor("off") == 0
    assert wordlist.mutation_factor("numbers") == 10
    assert wordlist.mutation_factor("symbols") == 17
    # "69" is already in the 00-99 group, so it is counted once.
    assert wordlist.mutation_factor("common") == 188
    assert wordlist.mutation_factor("all") == 190 + wordlist._LEET_MAX_FORMS


def test_iter_expansions_applies_case_and_mutation_to_the_same_candidate():
    expanded = list(
        wordlist.iter_expansions(iter([b"alpha", b"beta"]), "common", "numbers", 1)
    )

    assert expanded[:12] == [
        b"alpha",
        *[b"alpha" + tail for tail in wordlist._DIGIT_TAILS],
        b"Alpha",
    ]
    assert expanded[-1] == b"beta"
    assert len(expanded) == wordlist.expansion_count(
        2, "common", "numbers", 1
    )


def test_iter_expansions_without_a_prefix_expands_a_custom_list_fully():
    expanded = list(
        wordlist.iter_expansions(iter([b"love", b"mine"]), "common", "off")
    )

    assert expanded == [b"love", b"Love", b"LOVE", b"mine", b"Mine", b"MINE"]


def test_iter_expansions_off_is_a_pass_through():
    words = [b"love", b"Love"]
    assert list(wordlist.iter_expansions(iter(words), "off", "off")) == words
