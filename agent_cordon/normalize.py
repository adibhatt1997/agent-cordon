"""Normalization and decoding layers.

Attackers hide injections by obfuscating them: unicode homoglyphs, zero-width
characters, leetspeak, and base64 / hex / url / rot13 encoding. A scanner that
only matches raw text is trivial to bypass.

This module produces a set of *variants* of the input. The scanner runs every
detector against every variant, so an injection that is invisible in the raw
text becomes visible in a normalized or decoded variant.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass

# --- invisible / zero-width characters ------------------------------------

INVISIBLE_CHARS = (
    "​‌‍⁠﻿­᠎"
    "‎‏‪‫‬‭‮"  # bidi controls
)
INVISIBLE_RE = re.compile("[" + INVISIBLE_CHARS + "]")

# --- confusable / homoglyph folding ---------------------------------------
# Maps common Cyrillic / Greek / fullwidth look-alikes back to ASCII so that
# "іgnоrе" (with Cyrillic i and o) folds to "ignore".
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ј": "j", "һ": "h",
    "Ѕ": "s", "Β": "b", "Ε": "e", "Η": "h", "Ι": "i",
    "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p",
    "Τ": "t", "Χ": "x", "ο": "o", "α": "a", "ι": "i",
}
_CONFUSABLE_TABLE = {ord(k): v for k, v in CONFUSABLES.items()}

# --- leetspeak ------------------------------------------------------------
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                      "7": "t", "@": "a", "$": "s", "!": "i"})

# --- encoded payload detectors --------------------------------------------
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")


def strip_invisible(text: str) -> str:
    return INVISIBLE_RE.sub("", text)


def count_invisible(text: str) -> int:
    return len(INVISIBLE_RE.findall(text))


def fold_confusables(text: str) -> str:
    return text.translate(_CONFUSABLE_TABLE)


def deleet(text: str) -> str:
    return text.translate(LEET)


def count_mixed_script_words(text: str) -> int:
    """Count words that mix Latin with other scripts, a homoglyph tell."""
    n = 0
    for word in re.findall(r"\w{3,}", text):
        scripts = set()
        for ch in word:
            if ch.isascii() and ch.isalpha():
                scripts.add("latin")
            elif ord(ch) >= 0x0400 and ord(ch) <= 0x04FF:
                scripts.add("cyrillic")
            elif ord(ch) >= 0x0370 and ord(ch) <= 0x03FF:
                scripts.add("greek")
        if len(scripts) > 1:
            n += 1
    return n


def canonical(text: str) -> str:
    """The aggressive normalization used for matching.

    NFKC -> strip invisibles -> fold confusables. Case is left to the
    case-insensitive matchers.
    """
    text = unicodedata.normalize("NFKC", text)
    text = strip_invisible(text)
    text = fold_confusables(text)
    return text


def _looks_like_text(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t ")
    return printable / len(s) >= 0.85 and any(c.isalpha() for c in s)


@dataclass
class Variant:
    label: str          # "raw", "canonical", "deleet", "base64", "rot13", ...
    text: str
    confidence: float   # multiplier applied to findings from this variant
    derived: bool       # True if produced by decoding (a stronger signal)


def _try_decode_b64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        s = raw.decode("utf-8", errors="strict")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return s if _looks_like_text(s) else None


def _try_decode_hex(blob: str) -> str | None:
    try:
        s = bytes.fromhex(blob).decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None
    return s if _looks_like_text(s) else None


def decode_layers(text: str, max_depth: int = 3) -> list[Variant]:
    """Find and recursively decode encoded payloads hidden in the text.

    Returns derived variants for any base64 / hex / url / rot13 content that
    decodes to plausible text. Recurses so an injection encoded twice still
    surfaces.
    """
    found: list[Variant] = []
    seen: set[str] = {text}

    def recurse(s: str, depth: int, trail: str) -> None:
        if depth > max_depth:
            return

        # url-encoding: decode the whole string if it carries percent escapes
        if "%" in s and re.search(r"%[0-9a-fA-F]{2}", s):
            dec = urllib.parse.unquote(s)
            if dec != s and _looks_like_text(dec) and dec not in seen:
                seen.add(dec)
                label = f"{trail}url"
                found.append(Variant(label, dec, 1.0, True))
                recurse(dec, depth + 1, label + ":")

        # rot13: only useful if it changes the text into something readable
        rot = codecs.encode(s, "rot_13")
        if rot != s and rot not in seen:
            # We do not add rot13 as a standalone noisy variant; we let the
            # scanner test it but at reduced confidence (handled by caller).
            seen.add(rot)
            label = f"{trail}rot13"
            found.append(Variant(label, rot, 0.8, True))

        # base64 and hex blobs embedded anywhere in the string
        for m in _B64_RE.finditer(s):
            dec = _try_decode_b64(m.group(0))
            if dec and dec not in seen:
                seen.add(dec)
                label = f"{trail}base64"
                found.append(Variant(label, dec, 1.0, True))
                recurse(dec, depth + 1, label + ":")
        for m in _HEX_RE.finditer(s):
            dec = _try_decode_hex(m.group(0))
            if dec and dec not in seen:
                seen.add(dec)
                label = f"{trail}hex"
                found.append(Variant(label, dec, 1.0, True))
                recurse(dec, depth + 1, label + ":")

    recurse(text, 1, "")
    return found


def build_variants(
    text: str,
    *,
    enable_confusables: bool = True,
    enable_deleet: bool = True,
    enable_decoding: bool = True,
    max_decode_depth: int = 3,
) -> list[Variant]:
    """Build every variant the scanner should inspect."""
    variants: list[Variant] = [Variant("raw", text, 1.0, False)]

    canon = canonical(text) if enable_confusables else strip_invisible(text)
    if canon != text:
        variants.append(Variant("canonical", canon, 1.0, False))

    if enable_deleet:
        leet = deleet(canon)
        if leet != canon:
            variants.append(Variant("deleet", leet, 0.9, False))

    if enable_decoding:
        variants.extend(decode_layers(canon, max_depth=max_decode_depth))

    return variants
