"""Interactive terminal UI for DecryptRE.

Typing ``decryptre`` with no arguments starts this menu. Everything here uses
only the standard library, keeps working when stdout is redirected (it falls
back to a numbered prompt), and never touches the network.

Navigation: arrow keys or ``j``/``k`` move, ``1``-``9`` jump straight to that
item, Enter selects, ``q`` goes back, Ctrl+C quits.
"""

import os
import shutil
import sys
import textwrap
import unicodedata
from typing import List, Optional, Sequence, Tuple

from . import (
    __version__,
    classical,
    encodings,
    modern_crypto,
    openssl_compat,
    present,
    wordlist as wordlists,
    xor,
)
from .auto_detect import detect
from .cli import (
    OpenSSLScanStatus,
    _xor_wrapper,
    load_common_wordlist,
    read_input,
)
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

HINT = "  up/down or j/k move  ·  1-9 jump  ·  Enter select  ·  q back  ·  Ctrl+C quit"


# ---------------------------------------------------------------------------
# Terminal handling
# ---------------------------------------------------------------------------

def _is_tty() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


_ANSI_RESTORE = None


def _enable_ansi() -> bool:
    """Try to enable virtual-terminal output; True only when safe to rely on.

    On Windows the console mode is read first and only the VT bit is added, so
    unrelated flags are preserved. The previous mode is restored when the
    menu exits. If anything fails, callers fall back to append-only menus
    instead of writing raw escape sequences into the console.
    """
    global _ANSI_RESTORE
    _ANSI_RESTORE = None
    if os.name != "nt":
        return True
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        kernel32.GetStdHandle.restype = wintypes.HANDLE
        handle = kernel32.GetStdHandle(-11)
        kernel32.GetConsoleMode.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        original = mode.value
        if original & 0x0004:  # already enabled
            return True
        if not kernel32.SetConsoleMode(handle, original | 0x0004):
            return False
        _ANSI_RESTORE = (handle, original)
        return True
    except Exception:
        return False


def _restore_ansi() -> None:
    """Put the Windows console mode back if this menu changed it."""
    global _ANSI_RESTORE
    if not _ANSI_RESTORE:
        return
    handle, original = _ANSI_RESTORE
    _ANSI_RESTORE = None
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleMode(handle, original)
    except Exception:
        pass


def _terminal_width() -> int:
    """Current terminal width, safe when there is no real terminal."""
    try:
        return max(20, shutil.get_terminal_size(fallback=(80, 24)).columns)
    except OSError:
        return 80


def _cell_width(text: str) -> int:
    """Approximate display cells, counting wide CJK characters as two."""
    width = 0
    for char in text:
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def _fit_text(text: str, width: int) -> str:
    """Truncate to one physical row, with an ellipsis when needed."""
    if _cell_width(text) <= width:
        return text
    if width <= 3:
        return "." * max(0, width)
    kept = []
    used = 0
    for char in text:
        cells = 0 if unicodedata.combining(char) else (
            2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        )
        if used + cells > width - 3:
            break
        kept.append(char)
        used += cells
    return "".join(kept) + "..."


def _fit_option(prefix: str, option: str, width: int) -> str:
    """Fit an option on one row, keeping its trailing ``[method · level]``.

    The confidence suffix is the part users need to see; truncate the
    candidate preview before it rather than cutting the suffix off.
    """
    available = width - _cell_width(prefix)
    if available <= 0:
        return _fit_text(prefix + option, width)
    if _cell_width(option) <= available:
        return prefix + option
    split = option.rfind("   [")
    if split != -1:
        suffix = option[split:]
        room = available - _cell_width(suffix)
        if room >= 1:
            head = _fit_text(option[:split].rstrip(), room)
            return prefix + head + suffix
    return _fit_text(prefix + option, width)


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


def _menu_rows(
    title: str, options: Sequence[str], index: int, width: int
) -> List[str]:
    """Build a frame as physical terminal rows, never wider than ``width``.

    Every option is forced onto one row so the painted height is exact; the
    title and hint are wrapped and therefore contribute multiple rows.
    """
    rows = [""]
    if title:
        for line in title.splitlines():
            rows.extend(textwrap.wrap(f"  {line}", width=width) or [""])
        rows.append("")
    for position, option in enumerate(options):
        marker = "\u276f" if position == index else " "
        prefix = f"   {marker} {position + 1}. "
        rows.append(_fit_option(prefix, option, width))
    rows.append("")
    rows.extend(textwrap.wrap(HINT, width=width) or [HINT])
    return rows


def _paint_rows(rows: Sequence[str], previous_height: int) -> int:
    """Repaint exactly over the previous frame and return the new height."""
    parts = []
    if previous_height:
        parts.append(f"\033[{previous_height}A")
    for row in rows:
        parts.append("\r\033[2K" + row + "\n")
    if previous_height > len(rows):
        parts.append("\033[J")
    sys.stdout.write("".join(parts))
    sys.stdout.flush()
    return len(rows)


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


def menu(
    title: str, options: Sequence[str], default: int = 0
) -> Optional[int]:
    """Show a menu and return the chosen index, or None to go back.

    ``default`` preselects an option in the arrow-key menu. The append-only
    fallback has no selection marker, so it simply waits for a number.
    """
    if not options:
        return None
    if not _is_tty() or not _enable_ansi():
        # Append-only mode is less pretty but cannot desynchronise a console
        # that does not understand cursor movement.
        return _fallback_menu(title, options)

    index = min(max(default, 0), len(options) - 1)
    width = _terminal_width()
    sys.stdout.write("\033[?25l")
    height = _paint_rows(_menu_rows(title, options, index, width), 0)
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
                width = _terminal_width()
                height = _paint_rows(
                    _menu_rows(title, options, index, width), height
                )
    finally:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()
        _restore_ansi()


def ask(prompt: str) -> str:
    try:
        return input(f"  {prompt} ").strip()
    except EOFError:
        return ""


def pause() -> None:
    if _is_tty():
        ask("Press Enter to continue.")


def show(text: str) -> None:
    """Print full text with real newlines, but no terminal-corrupting bytes."""
    width = max(20, min(100, _terminal_width() - 6))
    print()
    safe = present.visible_controls(text).expandtabs(4)
    for line in safe.splitlines() or [""]:
        for wrapped in textwrap.wrap(line, width=width) or [""]:
            print(f"  {wrapped}")
    print()


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def _ordered(results: Sequence[Candidate]) -> List[Candidate]:
    """Deterministic ranking: verified first, then score, then signature."""
    return sorted(
        results,
        key=lambda candidate: (
            candidate.verified,
            candidate.score,
            candidate.signature(),
        ),
        reverse=True,
    )


def _results_screen(results: List[Candidate]) -> None:
    """Numbered result picker with arrow/number navigation."""
    results = _ordered(results)
    while True:
        labels = []
        for candidate in results:
            preview = present.preview_text(candidate.text)
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
            results = _ordered(_search(candidate.text, "", quiet=True))
            if not results:
                print("  Nothing further could be decoded from that.")
                return
            continue
        if action == 1:
            continue
        return


TIER_ORDER = ("small", "medium", "large", "5m", "10m", "50m", "100m")


def _choose_openssl_tier() -> Optional[str]:
    """Ask which passphrase tier to use for an OpenSSL blob."""
    labels: List[str] = []
    tiers: List[str] = []
    for tier in TIER_ORDER:
        try:
            count = wordlists.tier_count(tier)
            suffix = " (default)" if tier == "medium" else ""
            labels.append(f"{tier} - {count:,} candidates{suffix}")
        except wordlists.WordlistError:
            labels.append(f"{tier} - unavailable (local RockYou not installed)")
        tiers.append(tier)

    choice = menu(
        "OpenSSL blob detected. Choose a passphrase wordlist tier:",
        labels,
        default=1,
    )
    if choice is None:
        return None
    return tiers[choice]


def _scan_openssl_tier(
    text: str, tier: str, quiet: bool = False
) -> List[Candidate]:
    """Stream one tier against an OpenSSL blob, with the same worker defaults."""
    try:
        total = wordlists.tier_count(tier)

        def factory():
            return wordlists.iter_tier(tier)

    except wordlists.WordlistError as exc:
        print(f"  Cannot load the {tier} tier: {exc}")
        return []

    if not quiet:
        print(
            f"  Scanning the {tier} tier ({total:,} passphrases)...",
            flush=True,
        )
    return openssl_compat.dictionary_attack_stream(
        text,
        factory,
        total,
        top=2,
        progress=OpenSSLScanStatus(stream=sys.stdout, prefix="  "),
        workers=openssl_compat.default_workers(),
    )


def _search(
    text: str, key: str, quiet: bool = False, tier: Optional[str] = None
) -> List[Candidate]:
    """Decrypt ``text`` and return the best candidates."""
    if tier and not key and openssl_compat.looks_like(text):
        return _scan_openssl_tier(text, tier, quiet=quiet)

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
        wordlist=[] if key else load_common_wordlist(),
        passphrase=key or None,
        openssl_progress=OpenSSLScanStatus(stream=sys.stdout, prefix="  "),
    )
    for candidate in found:
        if all(candidate.text != existing.text for existing in results):
            results.append(candidate)
    results.sort(
        key=lambda candidate: (
            candidate.verified,
            candidate.score,
            candidate.signature(),
        ),
        reverse=True,
    )
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

    tier = None
    if not key and openssl_compat.looks_like(text):
        tier = _choose_openssl_tier()
        if tier is None:
            return

    results = _search(text, key, tier=tier)
    if not results:
        if tier:
            print(
                f"  No passphrase in the {tier} tier opened this blob. "
                "Try a larger tier or supply the passphrase."
            )
        else:
            print(
                "  Nothing decoded. Try the CLI with --max-depth 4 or an "
                "explicit method."
            )
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
    decryptre decrypt --input "U2FsdGVkX1..." --key "pass"   # OpenSSL blob
    decryptre encrypt --input "TEXT" --method aes --key "pass"
    decryptre identify --input "5d41402abc4b2a76b9719d911017c592"
    decryptre methods                                every method and example
    decryptre --help                                 full reference

  Tips

    * --input takes text, a file path, or - to read stdin.
    * With --key, auto mode also opens AES/Fernet/3DES containers and the
      cipher verifies the passphrase, so the result is marked high confidence.
    * For OpenSSL blobs without a passphrase, the UI asks for a wordlist tier
      from 10,001 entries through the generated 100M tier.
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
