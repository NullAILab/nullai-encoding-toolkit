"""
main.py — Multi-format encoding CLI.

Usage
-----
    python main.py encode <text> [--fmt FORMAT]
    python main.py decode <text> [--fmt FORMAT]
    python main.py detect <text>
    python main.py all    <text>

    cat file.bin | python main.py encode --fmt hex
    echo "SGVsbG8=" | python main.py decode --fmt base64

Formats
-------
    base64     Standard Base64 (RFC 4648)
    base64url  URL-safe Base64 (RFC 4648 §5)
    hex        Hexadecimal
    binary     Space-separated 8-bit binary groups
    url        Percent-encoding (URL encoding)
    html       HTML entity encoding
    rot13      ROT13 substitution
    raw        Plain UTF-8 (no transformation)
"""

from __future__ import annotations

import argparse
import sys

from codec import Format, decode, detect, encode

_RESET  = "\033[0m"
_GREEN  = "\033[92m"
_CYAN   = "\033[96m"
_YELLOW = "\033[93m"
_DIM    = "\033[2m"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read_input(args: argparse.Namespace) -> str:
    """Return the input text from the positional arg or stdin."""
    if hasattr(args, "text") and args.text:
        return args.text
    if not sys.stdin.isatty():
        return sys.stdin.read()
    print("[!] Provide text as an argument or pipe it via stdin.", file=sys.stderr)
    sys.exit(1)


def _fmt_from_str(s: str) -> Format:
    try:
        return Format(s.lower())
    except ValueError:
        valid = ", ".join(Format.names())
        print(f"[!] Unknown format {s!r}. Valid options: {valid}", file=sys.stderr)
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Sub-commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_encode(args: argparse.Namespace) -> None:
    text = _read_input(args)
    fmt  = _fmt_from_str(args.fmt)
    result = encode(text.rstrip("\n") if sys.stdin.isatty() else text, fmt)
    print(result)


def cmd_decode(args: argparse.Namespace) -> None:
    text = _read_input(args).strip()
    fmt  = _fmt_from_str(args.fmt)
    try:
        raw = decode(text, fmt)
    except Exception as exc:
        print(f"[!] Decode failed: {exc}", file=sys.stderr)
        sys.exit(1)

    # Try to print as UTF-8; fall back to hex if binary data
    try:
        print(raw.decode("utf-8"))
    except UnicodeDecodeError:
        print(raw.hex())


def cmd_detect(args: argparse.Namespace) -> None:
    text = _read_input(args).strip()
    fmt  = detect(text)
    print(f"{_GREEN}Detected:{_RESET} {fmt.value}")

    # Attempt to show decoded output
    try:
        raw    = decode(text, fmt)
        sample = raw[:200]
        try:
            decoded = sample.decode("utf-8")
            print(f"{_DIM}Decoded:  {decoded!r}{_RESET}")
        except UnicodeDecodeError:
            print(f"{_DIM}Decoded:  {sample.hex()!r}  (binary){_RESET}")
    except Exception:
        pass


def cmd_all(args: argparse.Namespace) -> None:
    """Show the input encoded in every supported format."""
    text = _read_input(args)
    raw  = text.rstrip("\n").encode("utf-8")

    print(f"\n{_CYAN}Input:{_RESET} {text.rstrip()!r}\n")
    print(f"{'Format':<12}  {'Encoded value'}")
    print(f"{'─' * 12}  {'─' * 60}")

    for fmt in Format:
        if fmt == Format.RAW:
            continue
        try:
            result = encode(raw, fmt)
            # Truncate long outputs in the table
            display = result if len(result) <= 72 else result[:69] + "…"
            print(f"{_YELLOW}{fmt.value:<12}{_RESET}  {display}")
        except Exception as exc:
            print(f"{fmt.value:<12}  (error: {exc})")


# ─────────────────────────────────────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Encode, decode, and detect text across multiple formats.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="command", required=True)

    # encode
    enc = sub.add_parser("encode", help="Encode text to a format")
    enc.add_argument("text", nargs="?", default="", help="Text to encode (or pipe via stdin)")
    enc.add_argument("--fmt", default="base64",
                     help=f"Output format  (default: base64)  choices: {', '.join(Format.names())}")

    # decode
    dec = sub.add_parser("decode", help="Decode encoded text")
    dec.add_argument("text", nargs="?", default="", help="Text to decode (or pipe via stdin)")
    dec.add_argument("--fmt", default="base64",
                     help=f"Input format  (default: base64)  choices: {', '.join(Format.names())}")

    # detect
    det = sub.add_parser("detect", help="Auto-detect the encoding of unknown text")
    det.add_argument("text", nargs="?", default="", help="Text to analyse")

    # all
    sub.add_parser("all", help="Show input encoded in every format") \
       .add_argument("text", nargs="?", default="", help="Text to encode")

    return p


def main() -> None:
    args = build_parser().parse_args()

    dispatch = {
        "encode": cmd_encode,
        "decode": cmd_decode,
        "detect": cmd_detect,
        "all":    cmd_all,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
