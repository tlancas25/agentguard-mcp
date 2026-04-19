"""Canonicalization helpers used before pattern matching.

Defeats the common evasion techniques that broke v0.1.x detectors:
- Unicode homoglyphs / fullwidth / compatibility forms (NFKC)
- Zero-width joiners, zero-width spaces, word-joiner, BOM
- Non-breaking space and friends
- Base64, hex, URL, rot13 wrappers

We expand the text rather than replace it: the original string is always
scanned, plus any successful decodings, plus a stripped+casefolded variant.
detect() callers take the max score across all variants.

None of these layers are perfect. They exist to raise the bar past trivial
evasion — motivated attackers who defeat them should still be caught by
policy rules and the upstream-response signatures.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
import urllib.parse
from typing import Any, Iterable

ZERO_WIDTH_CHARS = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
    "\ufeff",  # BOM / zero width no-break space
}

SPACELIKE_CHARS = {
    "\u00a0",  # non-breaking space
    "\u2002", "\u2003", "\u2004", "\u2005", "\u2006",
    "\u2007", "\u2008", "\u2009", "\u200a",
    "\u202f", "\u205f", "\u3000",
}

_SPACELIKE_RE = re.compile("|".join(re.escape(c) for c in SPACELIKE_CHARS))
_ZWS_RE = re.compile("|".join(re.escape(c) for c in ZERO_WIDTH_CHARS))

_BASE64_PAT = re.compile(r"^[A-Za-z0-9+/=\s]{16,}$")
_HEX_PAT = re.compile(r"^[0-9a-fA-F\s]{32,}$")


def strip_invisible(text: str) -> str:
    """Remove zero-width controls and normalize weird whitespace to ASCII space."""
    text = _ZWS_RE.sub("", text)
    text = _SPACELIKE_RE.sub(" ", text)
    return text


def canonicalize(text: str) -> str:
    """Aggressive NFKC + strip-invisible + casefold for loose matching."""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = strip_invisible(normalized)
    return normalized.casefold()


def nfkc_stripped(text: str) -> str:
    """NFKC + strip-invisible but preserve case, so case-sensitive patterns
    (AWS key prefixes, GitHub token prefixes) still match after unicode
    cleanup."""
    return strip_invisible(unicodedata.normalize("NFKC", text))


def despaced(text: str) -> str:
    """All whitespace and ASCII-word separators removed.

    Purpose: catch fixed-shape tokens (AWS keys, SSNs, credit cards) that
    an attacker split with spaces, NBSPs, dashes or punctuation.
    """
    # Also strips the record-separator used by concatenated() so split
    # payloads become a single contiguous token.
    return re.sub(r"[\s\-._\u241e\u2010-\u2015\u2212]+", "", nfkc_stripped(text))


def _maybe_base64(text: str) -> list[str]:
    """Try to decode base64 blobs in the text. Returns extracted UTF-8 pieces."""
    out: list[str] = []
    for candidate in re.findall(r"[A-Za-z0-9+/=]{16,}", text):
        stripped = candidate.strip()
        if not _BASE64_PAT.match(stripped):
            continue
        try:
            padded = stripped + "=" * (-len(stripped) % 4)
            decoded = base64.b64decode(padded, validate=False)
            out.append(decoded.decode("utf-8", errors="ignore"))
        except (binascii.Error, ValueError):
            continue
    return out


def _maybe_hex(text: str) -> list[str]:
    out: list[str] = []
    for candidate in re.findall(r"[0-9a-fA-F]{32,}", text):
        if not _HEX_PAT.match(candidate):
            continue
        if len(candidate) % 2:
            continue
        try:
            decoded = bytes.fromhex(candidate)
            out.append(decoded.decode("utf-8", errors="ignore"))
        except (ValueError, UnicodeDecodeError):
            continue
    return out


def _maybe_rot13(text: str) -> list[str]:
    try:
        return [codecs.decode(text, "rot_13")]
    except Exception:
        return []


def _maybe_url_decode(text: str) -> list[str]:
    try:
        decoded = urllib.parse.unquote(text)
        return [decoded] if decoded != text else []
    except Exception:
        return []


def expand_variants(text: str) -> list[str]:
    """Return every form the same text could be matched in. Always non-empty.

    Case-sensitive detectors (e.g. AWS key prefixes) rely on the
    NFKC-stripped, case-preserved variant; the casefolded variant exists
    for detectors that use re.IGNORECASE. Decoded payloads are pushed
    through the same expansion.
    """
    if not isinstance(text, str) or not text:
        return [""]
    base: list[str] = [
        text,
        nfkc_stripped(text),
        canonicalize(text),
        despaced(text),
    ]
    for decoded in _maybe_base64(text):
        base.append(decoded)
        base.append(nfkc_stripped(decoded))
        base.append(canonicalize(decoded))
        base.append(despaced(decoded))
    for decoded in _maybe_hex(text):
        base.append(decoded)
        base.append(canonicalize(decoded))
    for decoded in _maybe_rot13(text):
        base.append(canonicalize(decoded))
    for decoded in _maybe_url_decode(text):
        base.append(canonicalize(decoded))
    # de-dup while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for v in base:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def iter_strings(value: Any) -> Iterable[str]:
    """Yield every string reachable inside an arbitrary nested structure.

    detectors need a flat view so adversaries can't sidestep detection by
    splitting payloads across dict keys or list elements.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from iter_strings(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from iter_strings(v)


def concatenated(value: Any, sep: str = " \u241e ") -> str:
    """Return every string in `value` joined with a record separator.

    Used so regex-based detectors see a single corpus, catching payloads
    that were split across arg keys. The separator is U+241E (SYMBOL FOR
    RECORD SEPARATOR), which patterns won't match on.
    """
    return sep.join(iter_strings(value))
