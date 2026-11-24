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
    monkeypatch.setattr(interactive.wordlists, "tier_count", lambda tier: 5_000_000)
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
    assert seen["total"] == 5_000_000
    assert seen["words"] == [b"alpha", b"beta"]
    assert seen["kwargs"]["top"] == 2
    assert seen["kwargs"]["workers"] == 7
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
