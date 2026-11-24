"""Interactive menu rendering: exact repaint height, stable order, safe text."""

import builtins
import re

from decryptre import interactive, present
from decryptre.models import Candidate


class _FakeStdout:
    def __init__(self):
        self.data = ""

    def write(self, text):
        self.data += text

    def flush(self):
        pass

    def isatty(self):
        return True


def _play_menu(monkeypatch, keys, title, options, width=40, default=0):
    fake = _FakeStdout()
    monkeypatch.setattr(interactive, "_is_tty", lambda: True)
    monkeypatch.setattr(interactive, "_enable_ansi", lambda: True)
    monkeypatch.setattr(interactive, "_restore_ansi", lambda: None)
    monkeypatch.setattr(interactive, "_terminal_width", lambda: width)
    monkeypatch.setattr(interactive.sys, "stdout", fake)
    feed = iter(keys)
    monkeypatch.setattr(interactive, "_read_key", lambda: next(feed))
    result = interactive.menu(title, options, default=default)
    return fake.data, result


def test_redraw_moves_up_exactly_the_previous_physical_height(monkeypatch):
    title = "Pick the result that looks right:"
    options = [f"candidate {index} " + "x" * 60 for index in range(7)]

    data, result = _play_menu(
        monkeypatch, ["down", "down", "up", "enter"], title, options, width=40
    )

    assert result == 1
    moved = [int(value) for value in re.findall(r"\x1b\[(\d+)A", data)]
    expected = [
        len(interactive._menu_rows(title, options, 0, 40)),
        len(interactive._menu_rows(title, options, 1, 40)),
        len(interactive._menu_rows(title, options, 2, 40)),
    ]
    assert moved == expected


def test_menu_can_preselect_a_default_option(monkeypatch):
    _data, result = _play_menu(
        monkeypatch, ["enter"], "Pick:", ["small", "medium", "5m"], default=2
    )

    assert result == 2


def test_every_rendered_row_fits_the_terminal_width():
    title = "Pick the result that looks right:"
    options = ["short", "y" * 120, "wide \u4f60\u597d " + "z" * 80]

    for width in (20, 40, 80):
        rows = interactive._menu_rows(title, options, 0, width)
        assert rows
        assert all(interactive._cell_width(row) <= width for row in rows)


def test_long_label_keeps_the_confidence_suffix():
    label = (
        "x" * 120
        + "   [OpenSSL 3DES-CBC (MD5) \u00b7 high (unauthenticated)]"
    )
    rows = interactive._menu_rows("Pick:", [label], 0, 80)
    option_row = next(row for row in rows if "[OpenSSL" in row)

    assert option_row.endswith("high (unauthenticated)]")
    assert interactive._cell_width(option_row) <= 80


def test_result_indices_stay_bound_to_the_same_candidate(monkeypatch):
    def candidate(text, score):
        return Candidate(text, "caesar", {"shift": score}, score=score)

    base = [candidate("alpha", 9.0), candidate("bravo", 8.0), candidate("charlie", 7.0)]
    renders = []

    def fake_menu(title, options):
        renders.append(list(options))
        return None

    monkeypatch.setattr(interactive, "menu", fake_menu)

    interactive._results_screen(list(base))
    interactive._results_screen(base + [candidate("delta", 6.0)])
    interactive._results_screen(list(base))

    # The first three entries keep their positions when the list grows or
    # shrinks; each option string carries its own display number.
    assert renders[0][:3] == renders[1][:3] == renders[2]
    assert len(renders[0]) == len(set(renders[0]))


def test_tied_candidates_order_deterministically():
    first = Candidate("same text", "caesar", {"shift": 1}, score=-5.0)
    second = Candidate("same text", "atbash", {}, score=-5.0)

    forward = [candidate.signature() for candidate in interactive._ordered([first, second])]
    reverse = [candidate.signature() for candidate in interactive._ordered([second, first])]

    assert forward == reverse


def test_preview_is_single_line_and_escapes_control_characters():
    preview = present.preview_text(
        "line one\nline two\r\tend\x1b[31m literal \\n done"
    )

    assert "\n" not in preview
    assert "\r" not in preview
    assert "\t" not in preview
    assert "\x1b" not in preview
    assert "\\x1b" in preview
    assert "literal \\n" in preview
    assert len(preview) <= 48


def test_unconfirmed_ansi_falls_back_to_append_only_menu(monkeypatch, capsys):
    monkeypatch.setattr(interactive, "_is_tty", lambda: True)
    monkeypatch.setattr(interactive, "_enable_ansi", lambda: False)
    monkeypatch.setattr(builtins, "input", lambda prompt="": "2")

    assert interactive.menu("Pick:", ["alpha", "bravo", "charlie"]) == 1

    out = capsys.readouterr().out
    assert "\033" not in out
    assert "Pick:" in out
    assert "2. bravo" in out


def test_confidence_labels_separate_tags_from_padding_guesses():
    tag_verified = Candidate(
        "hello", "modern", {"alg": "aes-gcm"}, verified=True
    )
    fernet = Candidate("hello", "modern", {"alg": "fernet"}, verified=True)
    padding_only = Candidate(
        "hello", "modern", {"alg": "aes-cbc"}, verified=True
    )
    openssl = Candidate(
        "hello", "openssl", {"alg": "OpenSSL 3DES-CBC (MD5)"}, verified=True
    )
    english_guess = Candidate("hello there", "caesar", {"shift": 3}, score=-5.0)

    assert present.confidence(tag_verified)[0] == "verified"
    assert present.confidence(fernet)[0] == "verified"
    assert present.confidence(padding_only)[0] == "high (unauthenticated)"
    assert present.confidence(openssl)[0] == "high (unauthenticated)"
    assert present.confidence(english_guess)[0] == "high"
