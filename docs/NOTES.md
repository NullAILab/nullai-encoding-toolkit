# Architecture Notes — Encoding Swiss Army Knife

## Why these seven formats?

These are the encodings most frequently encountered in security work:

| Format | Where you see it |
|--------|-----------------|
| Base64 | JWT tokens, HTTP Basic Auth headers, email attachments (MIME), encoded payloads in malware |
| Base64URL | JWT `.` segments, OAuth tokens, URL-embedded binary data |
| Hex | Packet captures, shellcode representations, hash digests, memory dumps |
| Binary | CTF challenges, educational visualisation, bit-level analysis |
| URL-percent | Web request parameters, path traversal payloads, XSS vectors in URLs |
| HTML entities | XSS payloads in HTML context, encoded content in web responses |
| ROT13 | Obfuscated strings in scripts, historical encoding in Usenet |

## Detection order rationale

The `detect()` function checks in a specific order because some patterns overlap:

1. **Binary before hex** — `01001000` is valid both as binary and as hex (value 0x01001000).
   Binary is checked first because hex is more common and binary requires digit groups of 8.

2. **Hex before Base64** — `deadbeef` is valid Base64 (decodes to something), but it is
   almost certainly hex when it consists only of hex digits with even length.

3. **URL before Base64** — `%41%42%43` could theoretically be Base64 if the percent signs
   were stripped, but the presence of `%XX` is a strong URL signal.

4. **HTML before Base64** — `&amp;` contains `&`, `;` and letters, which could match Base64
   partially, but the entity pattern is specific.

5. **Base64URL before Base64** — URL-safe variant uses `-_` in place of `+/`. If those chars
   are present, the URL-safe alphabet is more specific.

6. **Base64 last among pattern formats** — The Base64 alphabet (A-Za-z0-9+/=) is very
   permissive. It is the penultimate check so it doesn't overwhelm more specific formats.

## Hex normalisation

The `_normalise_hex()` function strips:
- Leading `0x` or `\x` escape prefixes (C/Python literal syntax)
- Spaces and colons used as byte separators (Wireshark/tcpdump output)

This is done with a regex substitution before `bytes.fromhex()` so the underlying
decoder does not need to be changed.

## Base64 padding tolerance

The `=` padding in Base64 is technically required by RFC 4648 but is frequently omitted
in practice (JWT, URL-embedded base64).  The `_add_base64_padding()` helper adds the
correct number of `=` characters based on `len(s) % 4`:
- `% 4 == 0` → no padding needed
- `% 4 == 2` → add `==`
- `% 4 == 3` → add `=`
- `% 4 == 1` → invalid Base64 (but we let `b64decode` raise the error rather than silently padding)

## ROT13 is text-only

ROT13 is defined only for the 26 ASCII letters.  Digits, spaces, and symbols are passed
through unchanged.  Binary data is first decoded to UTF-8 (with replacement characters for
invalid bytes) before the ROT13 table is applied.  This matches standard ROT13 behaviour
in all Unix tools (`tr`, `python -c 'import codecs; codecs.encode(..., "rot13")'`).

## Match/case requires Python 3.10+

The `encode()` and `decode()` functions use structural pattern matching (`match/case`),
available from Python 3.10.  If Python 3.8/3.9 compatibility is required, replace
`match fmt:` blocks with `if/elif` chains — the logic is identical.
