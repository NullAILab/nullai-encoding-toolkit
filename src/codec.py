"""
codec.py — Multi-format encoding / decoding library.

Supports Base64, URL-safe Base64, Hex, Binary, URL-percent, HTML entity, and
ROT13 formats.  Includes a heuristic ``detect()`` function that identifies the
most likely encoding of an unknown string — useful when working with encoded
payloads in CTF challenges, log analysis, or malware investigation.

No external dependencies.
"""

from __future__ import annotations

import base64
import html
import re
import urllib.parse
from enum import Enum
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Format enum
# ─────────────────────────────────────────────────────────────────────────────

class Format(str, Enum):
    BASE64    = "base64"
    BASE64URL = "base64url"
    HEX       = "hex"
    BINARY    = "binary"
    URL       = "url"
    HTML      = "html"
    ROT13     = "rot13"
    RAW       = "raw"

    @classmethod
    def names(cls) -> list[str]:
        return [f.value for f in cls]


_ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


# ─────────────────────────────────────────────────────────────────────────────
# Encode
# ─────────────────────────────────────────────────────────────────────────────

def encode(data: bytes | str, fmt: Format) -> str:
    """
    Encode *data* into the target format.

    Args:
        data: Raw bytes or a UTF-8 string to encode.
        fmt:  Target :class:`Format`.

    Returns:
        Encoded string.

    Raises:
        ValueError: For unknown formats (should not happen with the enum).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    match fmt:
        case Format.BASE64:
            return base64.b64encode(data).decode()

        case Format.BASE64URL:
            return base64.urlsafe_b64encode(data).decode()

        case Format.HEX:
            return data.hex()

        case Format.BINARY:
            # Space-separated 8-bit groups
            return " ".join(f"{byte:08b}" for byte in data)

        case Format.URL:
            # Percent-encode everything including slashes
            return urllib.parse.quote(data, safe="")

        case Format.HTML:
            text = data.decode("utf-8", errors="replace")
            return html.escape(text, quote=True)

        case Format.ROT13:
            # ROT13 is text-only; encode as UTF-8 first
            text = data.decode("utf-8", errors="replace")
            return text.translate(_ROT13_TABLE)

        case Format.RAW:
            return data.decode("utf-8", errors="replace")

        case _:
            raise ValueError(f"Unsupported format: {fmt!r}")


# ─────────────────────────────────────────────────────────────────────────────
# Decode
# ─────────────────────────────────────────────────────────────────────────────

def decode(data: str, fmt: Format) -> bytes:
    """
    Decode an encoded string back to raw bytes.

    Args:
        data: Encoded string.
        fmt:  Source :class:`Format`.

    Returns:
        Raw bytes.

    Raises:
        ValueError: If the string does not conform to the expected format.
    """
    match fmt:
        case Format.BASE64:
            # Tolerate missing padding
            padded = _add_base64_padding(data)
            return base64.b64decode(padded)

        case Format.BASE64URL:
            padded = _add_base64_padding(data)
            return base64.urlsafe_b64decode(padded)

        case Format.HEX:
            cleaned = _normalise_hex(data)
            return bytes.fromhex(cleaned)

        case Format.BINARY:
            groups = re.findall(r"[01]{8}", data)
            if not groups:
                if data.strip() == "":
                    return b""
                raise ValueError("No 8-bit binary groups found in input")
            return bytes(int(g, 2) for g in groups)

        case Format.URL:
            return urllib.parse.unquote_to_bytes(data)

        case Format.HTML:
            return html.unescape(data).encode("utf-8")

        case Format.ROT13:
            return data.translate(_ROT13_TABLE).encode("utf-8")

        case Format.RAW:
            return data.encode("utf-8")

        case _:
            raise ValueError(f"Unsupported format: {fmt!r}")


# ─────────────────────────────────────────────────────────────────────────────
# Auto-detection
# ─────────────────────────────────────────────────────────────────────────────

def detect(data: str) -> Format:
    """
    Heuristically identify the most likely encoding of *data*.

    The detection order matters — more specific patterns (binary, hex) are
    checked before more permissive ones (base64).

    Returns:
        The most likely :class:`Format`.  Falls back to ``Format.RAW`` when
        nothing matches confidently.
    """
    stripped = data.strip()
    if not stripped:
        return Format.RAW

    # ── Binary ────────────────────────────────────────────────────────────
    # Consists entirely of 0/1 digits with optional spaces, length divisible by 8
    bin_digits = re.sub(r"\s+", "", stripped)
    if re.fullmatch(r"[01]+", bin_digits) and len(bin_digits) % 8 == 0 and len(bin_digits) >= 8:
        return Format.BINARY

    # ── Hex ───────────────────────────────────────────────────────────────
    # Handles: "deadbeef", "de ad be ef", "0xde 0xad", "\xde\xad"
    hex_clean = _normalise_hex(stripped)
    if re.fullmatch(r"[0-9a-fA-F]+", hex_clean) and len(hex_clean) % 2 == 0 and len(hex_clean) >= 2:
        return Format.HEX

    # ── URL percent-encoding ──────────────────────────────────────────────
    if re.search(r"%[0-9A-Fa-f]{2}", stripped):
        return Format.URL

    # ── HTML entities ─────────────────────────────────────────────────────
    if re.search(r"&(?:[a-zA-Z]+|#\d+|#x[0-9A-Fa-f]+);", stripped):
        return Format.HTML

    # ── URL-safe Base64 ───────────────────────────────────────────────────
    # Must contain - or _ (the URL-safe substitutions for + and /)
    if re.fullmatch(r"[A-Za-z0-9_\-]+=*", stripped) and (
        "_" in stripped or "-" in stripped
    ):
        return Format.BASE64URL

    # ── Standard Base64 ───────────────────────────────────────────────────
    # Alphabet: A-Z a-z 0-9 + /   with optional = padding
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", stripped) and len(stripped.rstrip("=")) >= 4:
        return Format.BASE64

    return Format.RAW


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _add_base64_padding(s: str) -> str:
    """Return *s* with the correct number of ``=`` padding characters."""
    s = s.strip()
    remainder = len(s) % 4
    if remainder == 2:
        return s + "=="
    if remainder == 3:
        return s + "="
    return s


def _normalise_hex(s: str) -> str:
    """
    Strip common hex decorations so ``bytes.fromhex()`` can parse the result.

    Handles: spaces, ``0x`` prefix per byte, ``\\x`` escape sequences.
    """
    s = s.strip()
    # Remove \x or 0x prefixes before each byte
    s = re.sub(r"(?:0x|\\x)", "", s, flags=re.IGNORECASE)
    # Remove spaces and colons (e.g. "de:ad:be:ef")
    s = re.sub(r"[\s:]", "", s)
    return s
