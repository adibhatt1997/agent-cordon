"""Detectors: independent signals that each emit Findings.

The scanner runs these over every normalized/decoded variant of the input and
aggregates the results. New detectors only need a `name` and a `detect()`.
"""

from __future__ import annotations

import re
from typing import Iterable

from .models import Finding
from .normalize import count_invisible, count_mixed_script_words
from .rules import ROLE_MARKER_RE, RULES, Rule

# Bidirectional control characters used in "Trojan Source" attacks: they can
# reorder how text renders versus how a model/compiler reads it.
BIDI_RE = re.compile("[‪‫‬‭‮⁦⁧⁨⁩‎‏]")

_B64_PRESENT = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_PRESENT = re.compile(r"(?:[0-9a-fA-F]{2}){24,}")

# Structural directive markers: imperative phrases aimed at the assistant.
_DIRECTIVE_MARKERS = [
    re.compile(p, re.IGNORECASE) for p in (
        r"\byou must\b", r"\byour task is\b", r"\byou should now\b",
        r"\byou are (now |required |instructed )", r"\bfrom now on\b",
        r"\bdo not (tell|reveal|mention|inform)\b", r"\byou will\b.{0,20}\b(comply|obey|instead)\b",
    )
]


class PatternDetector:
    name = "pattern"

    def __init__(self, rules: Iterable[Rule] = RULES):
        self.rules = list(rules)

    def detect(self, text: str, layer: str) -> list[Finding]:
        out: list[Finding] = []
        for rule in self.rules:
            for m in rule.pattern.finditer(text):
                snippet = m.group(0).strip()
                if len(snippet) > 140:
                    snippet = snippet[:137] + "..."
                out.append(Finding(
                    detector=self.name, rule_id=rule.id, category=rule.category,
                    description=rule.description, severity=rule.severity,
                    confidence=rule.confidence, snippet=snippet, layer=layer,
                    start=m.start(), end=m.end(),
                ))
        return out


class RoleMarkerDetector:
    name = "role_marker"

    def detect(self, text: str, layer: str) -> list[Finding]:
        out: list[Finding] = []
        for m in ROLE_MARKER_RE.finditer(text):
            out.append(Finding(
                detector=self.name, rule_id="role_marker", category="role_hijack",
                description="Chat/role control marker embedded in external data",
                severity=4, confidence=0.7, snippet=m.group(0).strip(),
                layer=layer, start=m.start(), end=m.end(),
            ))
        return out


class StructuralDetector:
    name = "structural"

    def detect(self, text: str, layer: str) -> list[Finding]:
        hits = [p.pattern for p in _DIRECTIVE_MARKERS if p.search(text)]
        if len(hits) >= 3:
            return [Finding(
                detector=self.name, rule_id="directive_pileup",
                category="instruction_override",
                description=f"Dense pile-up of {len(hits)} imperative directives aimed at the assistant",
                severity=2, confidence=0.5, snippet="<multiple directive phrases>",
                layer=layer,
            )]
        return []


class ObfuscationDetector:
    """Runs on the raw text only: signals that something is being hidden."""

    name = "obfuscation"

    def detect(self, text: str, layer: str = "raw") -> list[Finding]:
        out: list[Finding] = []

        inv = count_invisible(text)
        if inv:
            out.append(Finding(
                detector=self.name, rule_id="invisible_chars", category="obfuscation",
                description=f"{inv} invisible/zero-width character(s) that can hide payloads",
                severity=3, confidence=min(1.0, 0.4 + 0.06 * inv),
                snippet="<invisible unicode>", layer=layer,
            ))

        bidi = len(BIDI_RE.findall(text))
        if bidi:
            out.append(Finding(
                detector=self.name, rule_id="bidi_override", category="obfuscation",
                description=f"{bidi} bidirectional control char(s) (Trojan-Source style reordering)",
                severity=4, confidence=min(1.0, 0.5 + 0.08 * bidi),
                snippet="<bidi control>", layer=layer,
            ))

        mixed = count_mixed_script_words(text)
        if mixed:
            out.append(Finding(
                detector=self.name, rule_id="mixed_script", category="obfuscation",
                description=f"{mixed} word(s) mixing scripts (homoglyph spoofing)",
                severity=3, confidence=min(1.0, 0.45 + 0.07 * mixed),
                snippet="<mixed-script text>", layer=layer,
            ))

        if _B64_PRESENT.search(text) or _HEX_PRESENT.search(text):
            out.append(Finding(
                detector=self.name, rule_id="encoded_blob", category="obfuscation",
                description="Long base64/hex blob that may carry an encoded payload",
                severity=2, confidence=0.4, snippet="<encoded blob>", layer=layer,
            ))
        return out
