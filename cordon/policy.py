"""Policy configuration for cordon.

A Policy bundles every knob: thresholds, what to decode, domain allow/deny
lists for the egress firewall, secret patterns, an allowlist to suppress false
positives, an optional second-stage LLM verifier, and a telemetry callback.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Pattern, Sequence

from .rules import Rule


@dataclass
class Policy:
    # risk thresholds
    suspicious_threshold: int = 25
    dangerous_threshold: int = 60

    # normalization / decoding
    enable_confusables: bool = True
    enable_deleet: bool = True
    enable_decoding: bool = True
    max_decode_depth: int = 3

    # detector toggles
    enable_structural: bool = True
    enable_bidi: bool = True
    enable_role_markers: bool = True

    # noise control
    min_confidence: float = 0.3
    allowlist: Sequence[Pattern[str]] = field(default_factory=list)

    # extension
    extra_rules: Sequence[Rule] = field(default_factory=list)

    # egress firewall
    allowed_domains: Sequence[str] = field(default_factory=list)  # empty = allow all
    blocked_domains: Sequence[str] = field(default_factory=list)

    # optional second-stage verifier: takes flagged text, returns 0..1 risk.
    # Called only for "gray zone" content to refine the score. Bring your own
    # (e.g. a small LLM classifier). Never called on clearly clean/dangerous text.
    verifier: Optional[Callable[[str], float]] = None
    verify_band: tuple[int, int] = (25, 60)  # risk range that triggers the verifier

    # telemetry: called once per scan with the ScanResult (for logging / SIEM / alerts)
    on_event: Optional[Callable[[object], None]] = None

    def allowlisted(self, snippet: str) -> bool:
        return any(p.search(snippet) for p in self.allowlist)

    @classmethod
    def strict(cls) -> "Policy":
        """Lower thresholds and full decoding. Use on fully untrusted sources."""
        return cls(suspicious_threshold=15, dangerous_threshold=45,
                   min_confidence=0.2, max_decode_depth=4)

    @classmethod
    def lenient(cls) -> "Policy":
        """Higher thresholds. Use when false positives are costly."""
        return cls(suspicious_threshold=35, dangerous_threshold=70,
                   min_confidence=0.45)


DEFAULT_POLICY = Policy()


def compile_allowlist(patterns: Sequence[str]) -> list[Pattern[str]]:
    """Helper to turn plain strings into compiled, case-insensitive patterns."""
    return [re.compile(p, re.IGNORECASE) for p in patterns]
