# Encoding Swiss Army Knife

A command-line tool for encoding, decoding, and auto-detecting text across
seven common formats — Base64, URL-safe Base64, Hex, Binary, URL-percent,
HTML entities, and ROT13.

> **Language:** Python 3.10+ &nbsp;|&nbsp; **Dependencies:** None (standard library only)

---

## The Problem

Security work involves constantly encountering encoded data — base64 in JWT
tokens, percent-encoding in HTTP logs, hex in packet captures, HTML entities
in XSS payloads.  Reaching for Python's `base64.b64decode()` or switching
between online tools breaks the analysis flow.  This tool keeps everything
in one place with a consistent interface.

---

## Who This Is For

| Audience | Use case |
|----------|----------|
| **CTF players** | Rapidly decode challenge payloads without switching tools |
| **Security analysts** | Decode obfuscated strings in malware, logs, or traffic |
| **Web developers** | Understand encoding differences between URL, HTML, and Base64 |
| **Students** | Visualise what Base64 and hex look like byte-by-byte |

---

## Project Structure

```
16-base64-encoder-decoder/
├── LICENSE
├── README.md
├── .gitignore
├── src/
│   ├── codec.py          ← Encoding library (importable)
│   ├── main.py           ← CLI entry point
│   └── test_codec.py     ← pytest suite (77 tests)
└── docs/
    └── NOTES.md
```

---

## Setup

```bash
git clone https://github.com/NullAILab/nullai-encoding-toolkit.git
cd nullai-encoding-toolkit/src
python main.py --help
```

No installation required.  Python 3.10+ is the only dependency.

---

## Usage

### Encode text

```bash
python main.py encode "Hello, World!"               # base64 (default)
python main.py encode "Hello, World!" --fmt hex
python main.py encode "Hello, World!" --fmt binary
python main.py encode "Hello, World!" --fmt url
python main.py encode "<script>alert(1)</script>" --fmt html
python main.py encode "Hello" --fmt rot13
```

### Decode text

```bash
python main.py decode "SGVsbG8sIFdvcmxkIQ=="         # base64 (default)
python main.py decode "48656c6c6f" --fmt hex
python main.py decode "01001000 01101001" --fmt binary
python main.py decode "Hello%2C%20World%21" --fmt url
python main.py decode "&lt;script&gt;" --fmt html
```

### Auto-detect the encoding

```bash
python main.py detect "SGVsbG8gV29ybGQ="
# Detected: base64
# Decoded:  'Hello World'

python main.py detect "48656c6c6f"
# Detected: hex
# Decoded:  'Hello'

python main.py detect "01001000 01101001"
# Detected: binary
# Decoded:  'Hi'
```

### Show all encodings at once

```bash
python main.py all "Hello"
```

```
Input: 'Hello'

Format        Encoded value
────────────  ────────────────────────────────────────────────────────────
base64        SGVsbG8=
base64url     SGVsbG8=
hex           48656c6c6f
binary        01001000 01100101 01101100 01101100 01101111
url           Hello
html          Hello
rot13         Uryyb
```

### Pipe-friendly

```bash
# Decode a JWT payload section (base64url without padding)
echo "eyJhbGciOiJIUzI1NiJ9" | python main.py decode --fmt base64url

# Encode a file as hex
cat /bin/sh | python main.py encode --fmt hex | head -c 100

# Detect and show decoded value in one step
echo "SGVsbG8gV29ybGQ=" | python main.py detect
```

---

## Supported Formats

| Format | Description | Example |
|--------|-------------|---------|
| `base64` | RFC 4648 standard Base64 | `SGVsbG8=` |
| `base64url` | RFC 4648 §5 URL-safe (uses `-_` instead of `+/`) | `SGVsbG8=` |
| `hex` | Lowercase hexadecimal | `48656c6c6f` |
| `binary` | Space-separated 8-bit groups | `01001000 01101001` |
| `url` | Percent-encoding (all non-safe chars encoded) | `Hello%2C%20World%21` |
| `html` | HTML entity encoding | `&lt;script&gt;` |
| `rot13` | ROT13 substitution cipher (text only) | `Uryyb` |

**Hex decoder** accepts multiple representations automatically:
- Plain: `48656c6c6f`
- Spaced: `48 65 6c 6c 6f`
- C-style: `\x48\x65\x6c\x6c\x6f`
- `0x`-prefixed: `0x48 0x65 0x6c 0x6c 0x6f`
- Colon-separated: `48:65:6c:6c:6f`

---

## Using `codec.py` as a Library

```python
from codec import encode, decode, detect, Format

# Encode
print(encode(b"Hello", Format.BASE64))          # SGVsbG8=
print(encode(b"Hello", Format.HEX))             # 48656c6c6f

# Decode
print(decode("SGVsbG8=", Format.BASE64))        # b'Hello'
print(decode("48 65 6c 6c 6f", Format.HEX))    # b'Hello' — spaced hex

# Auto-detect and decode unknown input
fmt = detect("SGVsbG8gV29ybGQ=")
print(fmt)                                      # Format.BASE64
print(decode("SGVsbG8gV29ybGQ=", fmt))         # b'Hello World'
```

---

## Running the Tests

```bash
cd src
pip install pytest   # one-time
pytest test_codec.py -v
```

Expected: **77 passed**.

Coverage includes:
- Round-trip encode→decode for every format across 6 input samples (including binary data and Unicode)
- Known expected outputs for each encoder
- Hex decoder with 5 different input styles (spaces, `0x`, `\x`, `:`, uppercase)
- Base64 decoder with 0, 1, and 2 missing padding characters
- Auto-detector accuracy for all 7 formats
- Empty-input and error-case handling

---

## Auto-Detection Algorithm

The `detect()` function applies pattern checks in priority order:

1. **Binary** — only `0`/`1` digits, length divisible by 8
2. **Hex** — only hex digits after stripping `0x`/`\x` prefixes, even length
3. **URL** — contains `%XX` sequences
4. **HTML** — contains `&name;` or `&#N;` entities
5. **Base64URL** — contains `-` or `_` (URL-safe alphabet chars)
6. **Base64** — only base64 alphabet with optional `=` padding
7. **Raw** — fallback

The order matters: `48656c6c6f` would match Base64 if hex weren't checked first,
since all hex digits are valid Base64 characters.

---

## Learning Objectives

- [ ] Understand what Base64 encodes — it is *encoding*, not *encryption*
- [ ] Understand the difference between Base64 and URL-safe Base64
- [ ] Understand why percent-encoding exists and where it is used
- [ ] Understand HTML entity encoding and its role in XSS prevention
- [ ] Understand why encoded data appears in malware, JWT tokens, and phishing payloads

---

## References

- [RFC 4648 — Base64 (IETF)](https://www.rfc-editor.org/rfc/rfc4648)
- [MDN — encodeURIComponent](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

---

## License

MIT — see [LICENSE](LICENSE).

---

*NullAI Lab — Encoding Swiss Army Knife*
