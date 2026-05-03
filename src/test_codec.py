"""
test_codec.py — pytest suite for codec.py

Run from the src/ directory:
    pytest test_codec.py -v
"""

import pytest
from codec import Format, decode, detect, encode, _add_base64_padding, _normalise_hex


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures / constants
# ─────────────────────────────────────────────────────────────────────────────

SAMPLES = [
    b"",
    b"A",
    b"Hello, World!",
    b"\x00\x01\x02\x03\xff\xfe",
    b"The quick brown fox jumps over the lazy dog",
    "Unicode: café élève".encode("utf-8"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Round-trip: encode then decode must recover the original bytes
# ─────────────────────────────────────────────────────────────────────────────

class TestRoundTrips:
    @pytest.mark.parametrize("data", SAMPLES)
    def test_base64_round_trip(self, data):
        assert decode(encode(data, Format.BASE64), Format.BASE64) == data

    @pytest.mark.parametrize("data", SAMPLES)
    def test_base64url_round_trip(self, data):
        assert decode(encode(data, Format.BASE64URL), Format.BASE64URL) == data

    @pytest.mark.parametrize("data", SAMPLES)
    def test_hex_round_trip(self, data):
        assert decode(encode(data, Format.HEX), Format.HEX) == data

    @pytest.mark.parametrize("data", SAMPLES)
    def test_binary_round_trip(self, data):
        assert decode(encode(data, Format.BINARY), Format.BINARY) == data

    @pytest.mark.parametrize("text", [
        "Hello", "test=value&other=1", "path/to/resource", "café"
    ])
    def test_url_round_trip(self, text):
        encoded = encode(text.encode(), Format.URL)
        assert decode(encoded, Format.URL) == text.encode("utf-8")

    @pytest.mark.parametrize("text", [
        "Hello <World>", '<script>alert("xss")</script>', "a & b", "café"
    ])
    def test_html_round_trip(self, text):
        encoded = encode(text.encode(), Format.HTML)
        assert decode(encoded, Format.HTML) == text.encode("utf-8")

    @pytest.mark.parametrize("text", [
        "Hello", "The quick brown fox", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    ])
    def test_rot13_self_inverse(self, text):
        """ROT13 applied twice recovers the original text."""
        once  = encode(text.encode(), Format.ROT13)
        twice = decode(once, Format.ROT13)
        assert twice == text.encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Encode — known expected outputs
# ─────────────────────────────────────────────────────────────────────────────

class TestEncodeOutputs:
    def test_base64_hello(self):
        assert encode(b"Hello", Format.BASE64) == "SGVsbG8="

    def test_base64url_differs_from_base64(self):
        # Base64url uses - and _ instead of + and /
        data = b"\xfb\xff"  # base64: +/8=  url-safe: -_8=
        b64    = encode(data, Format.BASE64)
        b64url = encode(data, Format.BASE64URL)
        assert b64 != b64url
        assert "-" in b64url or "_" in b64url

    def test_hex_hello(self):
        assert encode(b"Hello", Format.HEX) == "48656c6c6f"

    def test_binary_a(self):
        assert encode(b"A", Format.BINARY) == "01000001"

    def test_url_special_chars(self):
        result = encode(b"a b+c=d", Format.URL)
        assert " " not in result
        assert "+" not in result
        assert "=" not in result

    def test_html_escapes_lt_gt(self):
        result = encode(b"<b>bold</b>", Format.HTML)
        assert "<b>" not in result
        assert "&lt;b&gt;" in result

    def test_rot13_abc(self):
        assert encode(b"abc", Format.ROT13) == "nop"

    def test_rot13_nop_becomes_abc(self):
        assert encode(b"nop", Format.ROT13) == "abc"


# ─────────────────────────────────────────────────────────────────────────────
# Decode — edge cases and format variations
# ─────────────────────────────────────────────────────────────────────────────

class TestDecodeEdgeCases:
    def test_base64_missing_padding(self):
        # "SGVsbG8=" without the =
        assert decode("SGVsbG8", Format.BASE64) == b"Hello"

    def test_base64_missing_two_padding(self):
        # "SGk=" without padding
        assert decode("SGk", Format.BASE64) == b"Hi"

    def test_hex_uppercase(self):
        assert decode("48656C6C6F", Format.HEX) == b"Hello"

    def test_hex_with_spaces(self):
        assert decode("48 65 6c 6c 6f", Format.HEX) == b"Hello"

    def test_hex_with_0x_prefix(self):
        assert decode("0x48 0x65 0x6c 0x6c 0x6f", Format.HEX) == b"Hello"

    def test_hex_with_backslash_x(self):
        assert decode(r"\x48\x65\x6c\x6c\x6f", Format.HEX) == b"Hello"

    def test_hex_with_colon_separator(self):
        assert decode("48:65:6c:6c:6f", Format.HEX) == b"Hello"

    def test_binary_with_spaces(self):
        assert decode("01001000 01101001", Format.BINARY) == b"Hi"

    def test_binary_without_spaces(self):
        assert decode("0100100001101001", Format.BINARY) == b"Hi"

    def test_url_plus_sign(self):
        # %20 → space, + → + (url encoding; + in query strings means space but not here)
        assert decode("Hello%20World", Format.URL) == b"Hello World"

    def test_html_entities(self):
        assert decode("&lt;b&gt;", Format.HTML) == b"<b>"

    def test_html_numeric_entity(self):
        assert decode("&#72;ello", Format.HTML) == b"Hello"

    def test_binary_invalid_raises(self):
        with pytest.raises(ValueError):
            decode("not binary at all", Format.BINARY)


# ─────────────────────────────────────────────────────────────────────────────
# Auto-detection
# ─────────────────────────────────────────────────────────────────────────────

class TestDetect:
    def test_detects_base64(self):
        assert detect("SGVsbG8gV29ybGQ=") == Format.BASE64

    def test_detects_base64url(self):
        # URL-safe variant with _ or -
        assert detect("SGVsbG8-V29ybGQ_") == Format.BASE64URL

    def test_detects_hex_lowercase(self):
        assert detect("48656c6c6f") == Format.HEX

    def test_detects_hex_uppercase(self):
        assert detect("48656C6C6F") == Format.HEX

    def test_detects_hex_with_spaces(self):
        assert detect("48 65 6c 6c 6f") == Format.HEX

    def test_detects_binary(self):
        assert detect("01001000 01101001") == Format.BINARY

    def test_detects_url_encoding(self):
        assert detect("Hello%20World%21") == Format.URL

    def test_detects_html_entities(self):
        assert detect("&lt;script&gt;") == Format.HTML

    def test_detects_raw_plaintext(self):
        assert detect("Hello, World!") == Format.RAW

    def test_detects_empty_as_raw(self):
        assert detect("") == Format.RAW

    def test_detect_and_decode_base64(self):
        encoded = "SGVsbG8gV29ybGQ="
        fmt     = detect(encoded)
        assert decode(encoded, fmt) == b"Hello World"

    def test_detect_and_decode_hex(self):
        encoded = "48656c6c6f"
        fmt     = detect(encoded)
        assert decode(encoded, fmt) == b"Hello"


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_add_padding_no_change(self):
        assert _add_base64_padding("SGVs") == "SGVs"

    def test_add_padding_one_equal(self):
        assert _add_base64_padding("SGVsbG8") == "SGVsbG8="

    def test_add_padding_two_equals(self):
        assert _add_base64_padding("SGk") == "SGk="

    def test_normalise_hex_removes_spaces(self):
        assert _normalise_hex("48 65 6c") == "48656c"

    def test_normalise_hex_removes_0x_prefix(self):
        assert _normalise_hex("0x48 0x65") == "4865"

    def test_normalise_hex_removes_backslash_x(self):
        assert _normalise_hex(r"\x48\x65") == "4865"

    def test_normalise_hex_removes_colons(self):
        assert _normalise_hex("48:65:6c") == "48656c"


# ─────────────────────────────────────────────────────────────────────────────
# Format enum
# ─────────────────────────────────────────────────────────────────────────────

class TestFormat:
    def test_names_returns_all_formats(self):
        names = Format.names()
        assert "base64" in names
        assert "hex" in names
        assert "binary" in names
        assert "url" in names

    def test_from_string(self):
        assert Format("base64") == Format.BASE64
        assert Format("hex")    == Format.HEX
