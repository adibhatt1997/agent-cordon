"""Policy configuration for agent_cordon.

A Policy bundles every knob: thresholds, what to decode, domain allow/deny
lists for the egress firewall, secret patterns, an allowlist to suppress false
positives, an optional second-stage LLM verifier, and a telemetry callback.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from re import Pattern
from typing import Callable, Optional

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

    # resource limits (denial-of-service safety on attacker-controlled text)
    max_input_chars: int = 100_000   # text longer than this is truncated before scanning
    max_decode_variants: int = 24    # cap on decoded variants per scan
    max_blob_chars: int = 8192       # never decode a single base64/hex blob larger than this

    # detector toggles
    enable_structural: bool = True
    enable_bidi: bool = True
    enable_role_markers: bool = True

    # noise control
    min_confidence: float = 0.3
    allowlist: Sequence[Pattern[str]] = field(default_factory=list)

    # extension
    extra_rules: Sequence[Rule] = field(default_factory=list)

    # learned signatures from the feedback loop (see agent_cordon.feedback).
    # exact_benign holds canonical signatures of inputs a human confirmed are
    # safe (forced to risk 0); exact_attack holds signatures of inputs a human
    # confirmed are attacks (always flagged). This is how the feedback loop
    # guarantees a confirmed mistake never recurs.
    exact_benign: frozenset = field(default_factory=frozenset)
    exact_attack: frozenset = field(default_factory=frozenset)

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
    def strict(cls) -> Policy:
        """Lower thresholds and full decoding. Use on fully untrusted sources."""
        return cls(suspicious_threshold=15, dangerous_threshold=45,
                   min_confidence=0.2, max_decode_depth=4)

    @classmethod
    def lenient(cls) -> Policy:
        """Higher thresholds. Use when false positives are costly."""
        return cls(suspicious_threshold=35, dangerous_threshold=70,
                   min_confidence=0.45)

    # --- configuration loading (stdlib only) ------------------------------

    # Tunable fields that are safe to set from untrusted config (no callables,
    # no compiled patterns). Everything else stays at its default or is set in code.
    _SCALAR_FIELDS = (
        "suspicious_threshold", "dangerous_threshold",
        "enable_confusables", "enable_deleet", "enable_decoding",
        "max_decode_depth", "max_input_chars", "max_decode_variants",
        "max_blob_chars", "enable_structural", "enable_bidi",
        "enable_role_markers", "min_confidence",
    )

    @classmethod
    def from_mapping(cls, data: dict, *, base: Optional[Policy] = None) -> Policy:
        """Build a Policy from a plain dict (e.g. parsed JSON).

        Only known scalar knobs plus ``allowed_domains`` / ``blocked_domains`` /
        ``allowlist`` are honored; unknown keys are ignored so config files stay
        forward-compatible. ``allowlist`` entries are compiled as patterns.
        """
        p = base or cls()
        kwargs: dict = {}
        for k in cls._SCALAR_FIELDS:
            if k in data and data[k] is not None:
                kwargs[k] = data[k]
        for k in ("allowed_domains", "blocked_domains"):
            if k in data and data[k] is not None:
                kwargs[k] = list(data[k])
        if data.get("allowlist"):
            kwargs["allowlist"] = compile_allowlist(list(data["allowlist"]))
        return _replace_policy(p, kwargs)

    @classmethod
    def from_file(cls, path: str, *, base: Optional[Policy] = None) -> Policy:
        """Load a Policy from a JSON config file."""
        with open(path, encoding="utf-8") as fh:
            return cls.from_mapping(json.load(fh), base=base)

    @classmethod
    def from_env(cls, prefix: str = "AGENT_CORDON_", *,
                 base: Optional[Policy] = None) -> Policy:
        """Load knobs from environment variables, e.g. ``AGENT_CORDON_STRICT=1``.

        ``AGENT_CORDON_STRICT`` / ``AGENT_CORDON_LENIENT`` pick a preset; any
        ``AGENT_CORDON_<FIELD>`` overrides a scalar knob on top. Booleans accept
        1/0, true/false, yes/no; numbers are parsed as int or float.
        """
        env = os.environ
        p = base
        if p is None:
            if _env_bool(env.get(prefix + "STRICT")):
                p = cls.strict()
            elif _env_bool(env.get(prefix + "LENIENT")):
                p = cls.lenient()
            else:
                p = cls()
        data: dict = {}
        for k in cls._SCALAR_FIELDS:
            raw = env.get(prefix + k.upper())
            if raw is not None:
                data[k] = _coerce(getattr(p, k), raw)
        for k in ("allowed_domains", "blocked_domains"):
            raw = env.get(prefix + k.upper())
            if raw is not None:
                data[k] = [s.strip() for s in raw.split(",") if s.strip()]
        return cls.from_mapping(data, base=p)


def _replace_policy(p: Policy, kwargs: dict) -> Policy:
    from dataclasses import replace
    return replace(p, **kwargs)


def _env_bool(raw: Optional[str]) -> bool:
    return bool(raw) and raw.strip().lower() in ("1", "true", "yes", "on")


def _coerce(current, raw: str):
    """Coerce an env string to match the type of the current field value."""
    if isinstance(current, bool):
        return _env_bool(raw)
    if isinstance(current, int):
        return int(raw)
    if isinstance(current, float):
        return float(raw)
    return raw


DEFAULT_POLICY = Policy()


def compile_allowlist(patterns: Sequence[str]) -> list[Pattern[str]]:
    """Helper to turn plain strings into compiled, case-insensitive patterns."""
    return [re.compile(p, re.IGNORECASE) for p in patterns]
