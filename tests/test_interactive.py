import builtins

from decryptre import interactive
from decryptre.cli import main
from decryptre.models import Candidate


def test_bare_command_prints_help_when_input_is_not_a_terminal(capsys):
    assert main([]) == 0
    assert "usage: decryptre" in capsys.readouterr().out


def test_menu_falls_back_to_numbers_without_a_terminal(monkeypatch):
    monkeypatch.setattr(interactive, "_is_tty", lambda: False)
    monkeypatch.setattr(builtins, "input", lambda prompt="": "2")
    assert interactive.menu("Pick:", ["a", "b", "c"]) == 1


def test_menu_blank_answer_goes_back(monkeypatch):
    monkeypatch.setattr(interactive, "_is_tty", lambda: False)
    monkeypatch.setattr(builtins, "input", lambda prompt="": "")
    assert interactive.menu("Pick:", ["a", "b"]) is None


def test_menu_reprompts_on_bad_input(monkeypatch):
    monkeypatch.setattr(interactive, "_is_tty", lambda: False)
    answers = iter(["9", "x", "1"])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(answers))
    assert interactive.menu("Pick:", ["a", "b"]) == 0


def test_tier_menu_offers_generated_tiers_and_defaults_to_medium(monkeypatch):
    seen = {}

    def fake_menu(title, options, default=0):
        seen.update(title=title, options=list(options), default=default)
        return 3

    monkeypatch.setattr(interactive, "menu", fake_menu)

    assert interactive._choose_openssl_tier() == "5m"
    assert "OpenSSL blob detected" in seen["title"]
    assert seen["default"] == 1
    assert "5m - 5,000,000 candidates" in seen["options"]
    assert "100m - 100,000,000 candidates" in seen["options"]
    assert seen["options"][1].endswith("(default)")


def test_tier_menu_cancel_returns_none(monkeypatch):
    monkeypatch.setattr(interactive, "menu", lambda *args, **kwargs: None)
    assert interactive._choose_openssl_tier() is None


def test_tier_scan_streams_the_selected_tier(monkeypatch):
    seen = {}

    monkeypatch.setattr(interactive.openssl_compat, "looks_like", lambda text: True)
    counts = {"small": 10_001, "5m": 5_000_000}
    monkeypatch.setattr(interactive.wordlists, "tier_count", lambda tier: counts[tier])
    monkeypatch.setattr(
        interactive.wordlists, "iter_tier", lambda tier: iter([b"alpha", b"beta"])
    )
    monkeypatch.setattr(interactive.openssl_compat, "default_workers", lambda: 7)

    def fake_attack(text, factory, total, **kwargs):
        seen.update(text=text, total=total, words=list(factory()), kwargs=kwargs)
        return [
            Candidate(
                "readable plaintext",
                "openssl",
                {"passphrase": "alpha"},
                verified=True,
            )
        ]

    monkeypatch.setattr(
        interactive.openssl_compat, "dictionary_attack_stream", fake_attack
    )

    results = interactive._search("U2FsdGVkX1...", "", tier="5m")

    assert seen["text"] == "U2FsdGVkX1..."
    assert seen["total"] == 5_320_032
    assert seen["words"] == [b"alpha", b"beta"]
    assert seen["kwargs"]["top"] == 2
    assert seen["kwargs"]["workers"] == 7
    assert seen["kwargs"]["case_variants"] == "common"
    assert seen["kwargs"]["case_variant_prefix"] == 10_001
    assert seen["kwargs"]["mutations"] == "numbers"
    assert results[0].text == "readable plaintext"


def test_unavailable_tier_is_reported_without_traceback(monkeypatch, capsys):
    def missing(tier):
        raise interactive.wordlists.WordlistError("large tier is not installed")

    monkeypatch.setattr(interactive.wordlists, "tier_count", missing)

    assert interactive._scan_openssl_tier("blob", "large") == []
    assert "Cannot load the large tier" in capsys.readouterr().out


def test_decrypt_flow_prompts_for_a_tier_on_an_openssl_blob(monkeypatch):
    answers = iter(["U2FsdGVkX1...", ""])
    seen = {}
    monkeypatch.setattr(interactive, "ask", lambda prompt: next(answers))
    monkeypatch.setattr(interactive, "read_input", lambda value: value)
    monkeypatch.setattr(interactive.openssl_compat, "looks_like", lambda text: True)
    monkeypatch.setattr(interactive, "_choose_openssl_tier", lambda: "5m")
    monkeypatch.setattr(interactive, "pause", lambda: None)

    def fake_search(text, key, quiet=False, tier=None):
        seen.update(text=text, key=key, tier=tier)
        return []

    monkeypatch.setattr(interactive, "_search", fake_search)

    interactive.decrypt_flow()

    assert seen == {"text": "U2FsdGVkX1...", "key": "", "tier": "5m"}


def test_encrypt_flow_offers_to_save_the_exact_ciphertext(tmp_path, monkeypatch):
    target = tmp_path / "ciphertext.txt"
    answers = iter(["hello", str(target)])

    monkeypatch.setattr(interactive, "menu", lambda *args, **kwargs: 0)
    monkeypatch.setattr(interactive, "ask", lambda prompt: next(answers))
    monkeypatch.setattr(interactive, "show", lambda text: None)
    monkeypatch.setattr(interactive, "pause", lambda: None)

    interactive.encrypt_flow()

    expected = interactive.encodings.encode("hello", "base64")
    assert target.read_text(encoding="utf-8") == expected + "\n"


def test_decrypt_flow_skips_the_tier_prompt_when_key_is_known(monkeypatch):
    answers = iter(["U2FsdGVkX1...", "secret"])
    seen = {}
    monkeypatch.setattr(interactive, "ask", lambda prompt: next(answers))
    monkeypatch.setattr(interactive, "read_input", lambda value: value)
    monkeypatch.setattr(
        interactive,
        "_choose_openssl_tier",
        lambda: (_ for _ in ()).throw(AssertionError("tier should not be asked")),
    )

    def fake_search(text, key, quiet=False, tier=None):
        seen.update(key=key, tier=tier)
        return []

    monkeypatch.setattr(interactive, "_search", fake_search)
    monkeypatch.setattr(interactive, "pause", lambda: None)

    interactive.decrypt_flow()

    assert seen == {"key": "secret", "tier": None}


def test_tier_menu_names_an_authenticated_container(monkeypatch):
    seen = {}

    def fake_menu(title, options, default=0):
        seen.update(title=title, default=default, options=list(options))
        return 0

    monkeypatch.setattr(interactive, "menu", fake_menu)

    assert interactive._choose_tier("aes-gcm") == "small"
    assert "AES-256-GCM" in seen["title"]
    assert "Authenticated container detected" in seen["title"]
    assert seen["default"] == 0
    assert seen["options"][0].endswith("(default)")


def test_decrypt_flow_offers_a_tier_for_a_container(monkeypatch):
    answers = iter(["decryptre:v1:...", ""])
    seen = {}
    monkeypatch.setattr(interactive, "ask", lambda prompt: next(answers))
    monkeypatch.setattr(interactive, "read_input", lambda value: value)
    monkeypatch.setattr(interactive.openssl_compat, "looks_like", lambda text: False)
    monkeypatch.setattr(interactive, "is_container", lambda text: True)
    monkeypatch.setattr(interactive.modern_crypto, "container_alg", lambda text: "aes-gcm")
    monkeypatch.setattr(interactive, "_choose_tier", lambda kind: "small")
    monkeypatch.setattr(interactive, "pause", lambda: None)

    def fake_search(text, key, quiet=False, tier=None):
        seen.update(key=key, tier=tier)
        return []

    monkeypatch.setattr(interactive, "_search", fake_search)

    interactive.decrypt_flow()

    assert seen == {"key": "", "tier": "small"}


def test_modern_tier_scan_reports_an_estimate_and_streams(monkeypatch, capsys):
    seen = {}
    monkeypatch.setattr(interactive.wordlists, "tier_count", lambda tier: 10_001)
    monkeypatch.setattr(
        interactive.wordlists, "iter_tier", lambda tier: iter([b"love"])
    )
    monkeypatch.setattr(interactive.openssl_compat, "default_workers", lambda: 2)
    monkeypatch.setattr(
        interactive.modern_crypto, "container_alg", lambda text: "aes-gcm"
    )
    monkeypatch.setattr(
        interactive.modern_crypto,
        "estimate_attack_seconds",
        lambda text, total, workers: 8.0,
    )

    def fake_stream(text, factory, total, **kwargs):
        seen.update(total=total, kwargs=kwargs)
        return []

    monkeypatch.setattr(
        interactive.modern_crypto, "dictionary_attack_stream", fake_stream
    )

    assert interactive._scan_modern_tier("token", "small") == []
    out = capsys.readouterr().out
    assert "About 8s with 2 workers" in out
    assert "--mutations numbers|common" in out
    assert seen["total"] == 30_003
    assert seen["kwargs"]["workers"] == 2
    assert seen["kwargs"]["case_variants"] == "common"
    assert seen["kwargs"]["case_variant_prefix"] is None
    assert seen["kwargs"]["mutations"] == "off"


def test_modern_tier_scan_limits_expansion_to_the_small_prefix(monkeypatch):
    seen = {}
    counts = {"small": 10_001, "medium": 1_368_353}
    monkeypatch.setattr(interactive.wordlists, "tier_count", lambda tier: counts[tier])
    monkeypatch.setattr(
        interactive.wordlists, "iter_tier", lambda tier: iter([b"love"])
    )
    monkeypatch.setattr(interactive.openssl_compat, "default_workers", lambda: 1)
    monkeypatch.setattr(
        interactive.modern_crypto, "container_alg", lambda text: "aes-gcm"
    )

    def fake_stream(text, factory, total, **kwargs):
        seen.update(total=total, kwargs=kwargs)
        return []

    monkeypatch.setattr(
        interactive.modern_crypto, "dictionary_attack_stream", fake_stream
    )

    assert interactive._scan_modern_tier("token", "medium", quiet=True) == []
    assert seen["kwargs"]["case_variant_prefix"] == 10_001
    assert seen["total"] == interactive.wordlists.expansion_count(
        1_368_353, "common", "off", 10_001
    )
