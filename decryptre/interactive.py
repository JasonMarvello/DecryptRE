"""Interactive terminal UI for DecryptRE.

Typing ``decryptre`` with no arguments starts this menu. Everything here uses
only the standard library, keeps working when stdout is redirected (it falls
back to a numbered prompt), and never touches the network.

Navigation: arrow keys or ``j``/``k`` move, ``1``-``9`` jump straight to that
item, Enter selects, ``q`` goes back, Ctrl+C quits.
"""

import os
import sys
import textwrap
from typing import List, Optional, Sequence, Tuple

from . import __version__, classical, encodings, modern_crypto, present, xor
from .auto_detect import detect
from .cli import _xor_wrapper, load_wordlist, read_input
from .models import Candidate
from .scorer import score_text

BANNER = r"""
  ____                            _   ____  _____
 |  _ \  ___  ___ _ __ _   _ _ __| |_|  _ \| ____|
 | | | |/ _ \/ __| '__| | | | '__| __| |_) |  _|
 | |_| |  __/ (__| |  | |_| | |  | |_|  _ <| |___
 |____/ \___|\___|_|   \__, |_|   \__|_| \_\_____|
                       |___/   offline text recovery
"""

HINT = "  up/down or j/k move  ·  1-6 jump  ·  Enter select  ·  q back  ·  Ctrl+C quit"


# ---------------------------------------------------------------------------
# Terminal handling
# ---------------------------------------------------------------------------

def _is_tty() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _enable_ansi() -> None:
    """Turn on virtual-terminal escape codes on Windows 10+."""
    if os.name != "nt":
        return
    try:
        import ctypes

        handle = ctypes.windll.kernel32.GetStdHandle(-11)
        ctypes.windll.kernel32.SetConsoleMode(handle, 7)
    except Exception:
        pass


def _read_key() -> str:
    """Read one keypress and return a name: up/down/enter/back/quit or a char."""
    if os.name == "nt":
        import msvcrt

        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            code = msvcrt.getwch()
            return {"H": "up", "P": "down", "K": "left", "M": "right"}.get(code, "")
        if ch == "\r":
            return "enter"
        if ch == "\x03":
            raise KeyboardInterrupt
        if ch == "\x1b":
            return "back"
        return ch

    import select
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        # Read the file descriptor directly: the text wrapper buffers ahead,
        # which would make select() miss bytes and break arrow-key decoding.
        raw = os.read(fd, 1)
        if raw == b"\x03":
            raise KeyboardInterrupt
        if raw == b"\x1b":
            ready, _, _ = select.select([fd], [], [], 0.05)
            if not ready:
                return "back"
            seq = os.read(fd, 2).decode("ascii", "ignore")
            return {"[A": "up", "[B": "down", "[C": "right", "[D": "left"}.get(seq, "")
        if raw in (b"\r", b"\n"):
            return "enter"
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return raw.decode("utf-8", "ignore")


def _menu_lines(title: str, options: Sequence[str], index: int) -> List[str]:
    lines = [""]
    if title:
        lines.extend(f"  {line}" for line in title.splitlines())
        lines.append("")
    for position, option in enumerate(options):
        marker = "\u276f" if position == index else " "
        lines.append(f"   {marker} {position + 1}. {option}")
    lines.append("")
    lines.append(HINT)
    return lines


def _fallback_menu(title: str, options: Sequence[str]) -> Optional[int]:
    if title:
        print(title)
    for position, option in enumerate(options, start=1):
        print(f"  {position}. {option}")
    while True:
        try:
            answer = input("Choose a number (blank to go back): ").strip()
        except EOFError:
            return None
        if not answer:
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return int(answer) - 1
        print("  Please enter one of the numbers shown.")


def menu(title: str, options: Sequence[str]) -> Optional[int]:
    """Show a menu and return the chosen index, or None to go back."""
    if not _is_tty():
        return _fallback_menu(title, options)

    _enable_ansi()
    index = 0
    lines = _menu_lines(title, options, index)
    sys.stdout.write("\033[?25l")
    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.flush()
    try:
        while True:
            key = _read_key()
            moved = False
            if key in ("up", "k"):
                index = (index - 1) % len(options)
                moved = True
            elif key in ("down", "j"):
                index = (index + 1) % len(options)
                moved = True
            elif key == "enter":
                return index
            elif key in ("back", "q"):
                return None
            elif len(key) == 1 and key.isdigit():
                position = int(key) - 1
                if 0 <= position < len(options):
                    return position
            if moved:
                sys.stdout.write(f"\033[{len(lines)}A")
                lines = _menu_lines(title, options, index)
                for line in lines:
                    sys.stdout.write("\r\033[2K" + line + "\n")
                sys.stdout.flush()
    finally:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()


def ask(prompt: str) -> str:
    try:
        return input(f"  {prompt} ").strip()
    except EOFError:
        return ""


def pause() -> None:
    if _is_tty():
        ask("Press Enter to continue.")


def show(text: str) -> None:
    width = max(40, min(100, (os.get_terminal_size().columns if _is_tty() else 90) - 6))
    print()
    for line in text.splitlines() or [""]:
        for wrapped in textwrap.wrap(line, width=width) or [""]:
            print(f"  {wrapped}")
    print()


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def _results_screen(results: List[Candidate]) -> None:
    """Numbered result picker with arrow/number navigation."""
    while True:
        labels = []
        for candidate in results:
            preview = candidate.text.replace("\n", " ").strip()
            if len(preview) > 48:
                preview = preview[:45] + "..."
            name = present.display_name(candidate.method, candidate.params)
            level, _ = present.confidence(candidate)
            labels.append(f"{preview}   [{name} · {level}]")

        choice = menu("Pick the result that looks right:", labels)
        if choice is None:
            return

        candidate = results[choice]
        name = present.display_name(candidate.method, candidate.params)
        params = present.describe_params(candidate.method, candidate.params)
        level, note = present.confidence(candidate)
        print()
        print(f"  {name} {params}".rstrip())
        print(f"  confidence: {level} — {note}")
        if candidate.chain and candidate.depth:
            print(f"  path: {candidate.chain}")
        show(candidate.text)

        actions = [
            "Try this result again (another layer)",
            "Back to the list",
            "Back to the main menu",
        ]
        action = menu("What next?", actions)
        if action == 0:
            results = _search(candidate.text, "", quiet=True)
            if not results:
                print("  Nothing further could be decoded from that.")
                return
            continue
        if action == 1:
            continue
        return


def _search(text: str, key: str, quiet: bool = False) -> List[Candidate]:
    """Decrypt ``text`` and return the best candidates."""
    results: List[Candidate] = []
    if key:
        hit = modern_crypto.try_decrypt_any(text, key)
        if hit is not None:
            plain, alg = hit
            results.append(
                Candidate(
                    plain,
                    "modern",
                    {"alg": alg, "passphrase": key},
                    score_text(plain),
                    verified=True,
                )
            )

    if not quiet:
        print("  Searching offline (a few seconds for long text)...", flush=True)
    found = detect(
        text,
        max_depth=3,
        top=6,
        wordlist=[] if key else load_wordlist(),
        passphrase=key or None,
    )
    for candidate in found:
        if all(candidate.text != existing.text for existing in results):
            results.append(candidate)
    results.sort(key=lambda c: c.score, reverse=True)
    return results


def decrypt_flow() -> None:
    print()
    print("  Paste ciphertext, or type a file path. Multi-line input: use the CLI")
    print("  with --input - and pipe the text in.")
    text = ask("Ciphertext or file:")
    if not text:
        return
    text = read_input(text)
    key = ask("Passphrase, if you know it (blank to search):")

    results = _search(text, key)
    if not results:
        print("  Nothing decoded. Try the CLI with --max-depth 4 or an explicit method.")
        pause()
        return
    _results_screen(results)


ENCRYPT_METHODS: List[Tuple[str, str]] = [
    ("Base64", "base64"),
    ("Base32", "base32"),
    ("Hex", "base16"),
    ("Caesar / ROT-N", "caesar"),
    ("Atbash", "atbash"),
    ("Vigenere", "vigenere"),
    ("Rail Fence", "railfence"),
    ("XOR (passphrase)", "xor"),
    ("AES-256 (passphrase)", "aes"),
    ("3DES (passphrase, legacy)", "des3"),
    ("Fernet (passphrase)", "fernet"),
]


def encrypt_flow() -> None:
    labels = [label for label, _ in ENCRYPT_METHODS]
    choice = menu("Encrypt or encode with which method?", labels)
    if choice is None:
        return
    method = ENCRYPT_METHODS[choice][1]

    text = ask("Text to encrypt:")
    if not text:
        return

    try:
        if method in encodings.ENCODINGS:
            output = encodings.encode(text, method)
        elif method == "caesar":
            shift = ask("Shift (default 3):")
            output = classical.caesar_encrypt(text, int(shift) if shift.isdigit() else 3)
        elif method == "atbash":
            output = classical.atbash(text)
        elif method == "railfence":
            rails = ask("Rails (default 4):")
            output = classical.railfence_encrypt(text, int(rails) if rails.isdigit() else 4)
        else:
            key = ask("Passphrase:")
            if not key:
                print("  A passphrase is required for this method.")
                pause()
                return
            if method == "vigenere":
                output = classical.vigenere_encrypt(text, key)
            elif method == "xor":
                output = _xor_wrapper(xor.xor_encrypt(text, key))
            elif method == "aes":
                output = modern_crypto.encrypt_aes(text, key)
            elif method == "des3":
                output = modern_crypto.encrypt_des3(text, key)
            else:
                output = modern_crypto.encrypt_fernet(text, key)
    except (ValueError, TypeError) as exc:
        print(f"  Could not encrypt: {exc}")
        pause()
        return

    print("\n  Ciphertext:\n")
    show(output)
    pause()


def identify_flow() -> None:
    text = ask("Hash or encoded string:")
    if not text:
        return
    text = read_input(text).strip()
    matches = modern_crypto.identify_hash(text)
    print(f"\n  input length: {len(text)}")
    if matches:
        for match in matches:
            print(f"    {match}")
    else:
        print("    no known encoding or hash shape detected")
    print("    note: hashes are one-way; DecryptRE identifies them but cannot reverse them")
    pause()


def help_screen() -> None:
    print(
        """
  Command line equivalents

    decryptre decrypt --input "TEXT"                auto search
    decryptre decrypt --input "TEXT" --method caesar
    decryptre decrypt --input "TEXT" --key "pass"   auto + known passphrase
    decryptre decrypt --input file.txt --method aes --key "pass"
    decryptre decrypt --input token.txt --method des3 --key "pass"
    decryptre encrypt --input "TEXT" --method aes --key "pass"
    decryptre identify --input "5d41402abc4b2a76b9719d911017c592"
    decryptre methods                                every method and example
    decryptre --help                                 full reference

  Tips

    * --input takes text, a file path, or - to read stdin.
    * With --key, auto mode also opens AES/Fernet/3DES containers and the
      cipher verifies the passphrase, so the result is marked high confidence.
    * Only DecryptRE (decryptre:v1:) containers can be opened this way.
    * 3DES exists for legacy data only; do not encrypt new data with it.
    * --top 10 shows more results; --max-depth 4 peels more layers.
    * Everything runs offline: no accounts, no keys, no network.

  Responsible use

    Decrypt only data you own or have permission to test.
        """
    )
    pause()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run() -> int:
    _enable_ansi()
    print(BANNER)
    print(f"  v{__version__}  ·  everything runs offline")
    options = [
        "Decrypt / decode text",
        "Encrypt text",
        "Identify a hash or encoding",
        "Help and examples",
        "Quit",
    ]
    while True:
        choice = menu("", options)
        if choice is None or choice == 4:
            print("\n  bye\n")
            return 0
        try:
            if choice == 0:
                decrypt_flow()
            elif choice == 1:
                encrypt_flow()
            elif choice == 2:
                identify_flow()
            else:
                help_screen()
        except KeyboardInterrupt:
            print("\n  interrupted\n")
            return 130


def main() -> int:
    try:
        return run()
    except KeyboardInterrupt:
        print("\n  interrupted\n")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
