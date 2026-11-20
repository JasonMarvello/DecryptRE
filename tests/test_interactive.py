import builtins

from decryptre import interactive
from decryptre.cli import main


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
