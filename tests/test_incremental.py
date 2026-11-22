"""Incremental (exhaustive) passphrase search tests."""

import base64
import io
import itertools
import string
import sys

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from decryptre import incremental, openssl_compat
from decryptre.cli import _confirm_incremental, main

MESSAGE = "The quick brown fox jumps over the lazy dog."


def _aes_blob(text=MESSAGE, passphrase="042"):
    salt = b"12345678"
    key, iv = openssl_compat.evp_bytes_to_key(
        passphrase.encode(), salt, 32, 16, "md5"
    )
    body = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(text.encode(), 16))
    return base64.b64encode(b"Salted__" + salt + body).decode("ascii")


def _run(token, charset, min_length, max_length, state_path, **kwargs):
    prepared = openssl_compat.prepare_legacy_attempt(token)
    state = incremental.SearchState.create(
        prepared.digest,
        charset,
        min_length,
        max_length,
        prepared.variant_count,
    )
    result = incremental.incremental_attack(
        state, prepared.try_passphrase, state_path, **kwargs
    )
    return result, state, prepared


def test_charset_defaults_combinations_and_order():
    assert incremental.resolve_charset(None) == (
        string.ascii_lowercase + string.ascii_uppercase + string.digits
    )
    assert incremental.resolve_charset(["lower", "lower", "upper"]) == (
        string.ascii_lowercase + string.ascii_uppercase
    )
    assert incremental.resolve_charset(["all"]) == (
        string.ascii_lowercase
        + string.ascii_uppercase
        + string.digits
        + string.punctuation
    )
    with pytest.raises(ValueError, match="unknown charset"):
        incremental.resolve_charset(["nope"])


def test_counts_are_exact_and_independent_of_speed():
    assert incremental.count_passphrases("0123456789", 1, 1) == 10
    assert incremental.count_passphrases("0123456789", 1, 3) == 1_110
    assert incremental.count_passphrases("0123456789", 2, 3) == 1_100
    assert incremental.count_passphrases("ab", 1, 3) == 2 + 4 + 8
    assert incremental.count_passphrases("a", 1, 1) == 1

    assert incremental.estimate_seconds(1_000, 100.0) == 10.0
    assert incremental.estimate_seconds(1, 0.5) == 2.0
    with pytest.raises(ValueError):
        incremental.estimate_seconds(1, 0)

    assert incremental.format_duration(0.001) == "<0.01 seconds"
    assert incremental.format_duration(3600) == "1.0 hours"
    assert incremental.format_duration(float("inf")) == "effectively forever"


def test_enumeration_matches_itertools_order_and_resumes_midway():
    charset = "ab"
    expected = ["".join(chars) for chars in itertools.product(charset, repeat=3)]
    assert list(incremental.enumerate_passphrases(charset, 3)) == expected
    assert (
        list(incremental.enumerate_passphrases(charset, 3, start=5))
        == expected[5:]
    )
    assert list(incremental.enumerate_passphrases(charset, 3, start=8)) == []
    with pytest.raises(ValueError):
        list(incremental.enumerate_passphrases(charset, 3, start=9))

    candidates = []
    for length in (1, 2):
        candidates.extend(incremental.enumerate_passphrases("0123456789", length))
    assert len(candidates) == len(set(candidates)) == 110
    assert [len(candidate) for candidate in candidates] == sorted(
        len(candidate) for candidate in candidates
    )


def test_length_cap_and_range_validation():
    incremental.validate_lengths(1, 6, False)
    incremental.validate_lengths(1, 7, True)
    with pytest.raises(ValueError, match="safe cap"):
        incremental.validate_lengths(1, 7, False)
    with pytest.raises(ValueError):
        incremental.validate_lengths(2, 1, False)
    with pytest.raises(ValueError):
        incremental.validate_lengths(0, 1, False)


def test_prepared_attempt_uses_shared_variants_and_decrypts():
    blob = _aes_blob(passphrase="7")
    prepared = openssl_compat.prepare_legacy_attempt(blob)
    assert prepared.variant_count == 2 * (
        len(openssl_compat.available_ciphers()) - 1
    )
    hit = prepared.try_passphrase("7")
    assert hit is not None
    assert hit[0] == MESSAGE
    assert prepared.try_passphrase("8") is None


@pytest.mark.parametrize(
    "charset,passphrase,max_length",
    [
        ("0123456789", "7", 1),
        ("0123456789", "042", 3),
        ("abcdefghijklmnopqrstuvwxyz", "zz", 2),
    ],
)
def test_finds_short_known_passphrases(
    tmp_path, charset, passphrase, max_length
):
    blob = _aes_blob(passphrase=passphrase)
    result, state, prepared = _run(
        blob,
        charset,
        1,
        max_length,
        tmp_path / "state.json",
    )
    assert result is not None
    found, hit = result
    assert found == passphrase
    assert hit[0] == MESSAGE
    assert state.complete
    saved = incremental.SearchState.load(tmp_path / "state.json")
    assert saved.complete


def test_interrupted_run_resumes_at_same_position_and_result(tmp_path):
    target = "42"

    def attempt(passphrase):
        return "hit" if passphrase == target else None

    baseline_state = incremental.SearchState.create(
        "digest", "0123456789", 1, 2, 1
    )
    baseline = incremental.incremental_attack(
        baseline_state,
        attempt,
        tmp_path / "baseline.json",
        checkpoint_seconds=10 ** 9,
        checkpoint_attempts=10 ** 9,
    )
    assert baseline == (target, "hit")

    seen = []

    def resumed_attempt(passphrase):
        seen.append(passphrase)
        return "hit" if passphrase == target else None

    interrupted_state = incremental.SearchState.create(
        "digest", "0123456789", 1, 2, 1
    )

    def stop_after_five(info):
        if info.passphrases_done >= 5:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        incremental.incremental_attack(
            interrupted_state,
            resumed_attempt,
            tmp_path / "resume.json",
            progress=stop_after_five,
            checkpoint_seconds=10 ** 9,
            checkpoint_attempts=1,
        )

    saved = incremental.SearchState.load(tmp_path / "resume.json")
    assert saved.complete is False
    assert saved.next_length == 1
    assert saved.skip == 5
    assert saved.passphrases_done == 5

    seen.clear()
    resumed = incremental.incremental_attack(
        saved,
        resumed_attempt,
        tmp_path / "resume.json",
        checkpoint_seconds=10 ** 9,
        checkpoint_attempts=10 ** 9,
    )
    assert resumed == baseline
    assert seen[0] == "5"
    assert incremental.SearchState.load(tmp_path / "resume.json").complete


def test_state_roundtrip_and_resume_validation(tmp_path):
    state = incremental.SearchState.create(
        "digest-a", "0123456789", 1, 2, 8
    )
    state.next_length = 2
    state.skip = 3
    state.passphrases_done = 13
    path = tmp_path / "state.json"
    state.save(path)
    assert incremental.SearchState.load(path) == state

    with pytest.raises(ValueError, match="different blob"):
        incremental.validate_resume(state, "digest-b", 8)
    with pytest.raises(ValueError, match="variant"):
        incremental.validate_resume(state, "digest-a", 14)

    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        incremental.SearchState.load(path)


def test_cli_requires_explicit_openssl_method():
    blob = _aes_blob(passphrase="7")
    with pytest.raises(SystemExit) as excinfo:
        main(["decrypt", "--input", blob, "--incremental", "--yes"])
    assert "requires --method openssl" in str(excinfo.value)

    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "decrypt",
                "--input",
                blob,
                "--method",
                "openssl",
                "--incremental",
                "--key",
                "7",
            ]
        )
    assert "cannot be combined with --key" in str(excinfo.value)


def test_cli_incremental_flags_require_the_mode():
    with pytest.raises(SystemExit) as excinfo:
        main(["decrypt", "--input", "hello", "--resume"])
    assert "require --incremental" in str(excinfo.value)


def test_cli_refuses_length_above_six_without_override():
    blob = _aes_blob(passphrase="7")
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "decrypt",
                "--input",
                blob,
                "--method",
                "openssl",
                "--incremental",
                "--max-length",
                "7",
                "--yes",
            ]
        )
    assert "--i-understand-the-risk" in str(excinfo.value)


def test_cli_requires_yes_for_long_estimate_when_not_a_tty(
    tmp_path, monkeypatch, capsys
):
    blob = _aes_blob(passphrase="7")
    monkeypatch.setattr(
        incremental,
        "measure_rate",
        lambda attempt: incremental.RateMeasurement(1e-6, 200, 0.1),
    )
    base = [
        "decrypt",
        "--input",
        blob,
        "--method",
        "openssl",
        "--incremental",
        "--charset",
        "digits",
        "--max-length",
        "1",
        "--state-file",
        str(tmp_path / "state.json"),
    ]
    with pytest.raises(SystemExit) as excinfo:
        main(base)
    assert "--yes" in str(excinfo.value)

    assert main(base + ["--yes"]) == 0
    captured = capsys.readouterr()
    assert MESSAGE in captured.out
    assert "Incremental passphrase search" in captured.err
    assert "Found with passphrase" in captured.err


def test_confirm_prompt_accepts_yes_and_rejects_no(monkeypatch, capsys):
    class TTY(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", TTY("n\n"))
    with pytest.raises(SystemExit) as excinfo:
        _confirm_incremental(3600)
    assert "cancelled" in str(excinfo.value)

    monkeypatch.setattr(sys, "stdin", TTY("y\n"))
    _confirm_incremental(3600)


def test_exhaustion_marks_state_complete_and_resume_reports_it(tmp_path):
    blob = _aes_blob(passphrase="x")
    base = [
        "decrypt",
        "--input",
        blob,
        "--method",
        "openssl",
        "--incremental",
        "--charset",
        "digits",
        "--max-length",
        "1",
        "--state-file",
        str(tmp_path / "state.json"),
    ]
    with pytest.raises(SystemExit) as excinfo:
        main(base + ["--yes"])
    assert "Exhausted" in str(excinfo.value)
    assert incremental.SearchState.load(tmp_path / "state.json").complete

    with pytest.raises(SystemExit) as excinfo:
        main(base + ["--resume"])
    assert "already complete" in str(excinfo.value)


def test_auto_mode_never_calls_incremental(monkeypatch, capsys):
    blob = _aes_blob(passphrase="7")

    def forbidden(*args, **kwargs):
        raise AssertionError("auto mode must never start incremental search")

    monkeypatch.setattr(incremental, "incremental_attack", forbidden)
    assert (
        main(
            [
                "decrypt",
                "--input",
                blob,
                "--no-wordlist",
                "--no-substitution",
            ]
        )
        == 0
    )
    assert "OpenSSL 'Salted__' blob" in capsys.readouterr().out
