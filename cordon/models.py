"""Shared data models for cordon."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    detector: str       # which detector produced it
    rule_id: str
    category: str
    description: str
    severity: int       # 1 (low) .. 5 (critical)
    confidence: float   # 0..1
    snippet: str
    layer: str = "raw"  # variant the match was found in (raw, canonical, base64, ...)
    start: int = -1
    end: int = -1

    @property
    def hidden(self) -> bool:
        """True when the match only surfaced after decoding/deobfuscation."""
        return self.layer not in ("raw", "canonical")


@dataclass
class ScanResult:
    text: str
    normalized: str
    findings: list[Finding] = field(default_factory=list)
    risk: int = 0
    variants_scanned: int = 1
    suspicious_threshold: int = 25
    dangerous_threshold: int = 60

    @property
    def is_suspicious(self) -> bool:
        return self.risk >= self.suspicious_threshold

    @property
    def is_dangerous(self) -> bool:
        return self.risk >= self.dangerous_threshold

    @property
    def categories(self) -> list[str]:
        return sorted({f.category for f in self.findings})

    def __bool__(self) -> bool:
        return bool(self.findings)

    def summary(self) -> str:
        if not self.findings:
            return "clean: no injection patterns detected (risk 0)"
        verdict = "DANGEROUS" if self.is_dangerous else (
            "suspicious" if self.is_suspicious else "low"
        )
        lines = [f"{verdict}: risk {self.risk}/100, {len(self.findings)} finding(s) "
                 f"across {len(self.categories)} categor(y/ies):"]
        for f in sorted(self.findings, key=lambda x: (-x.severity, -x.confidence)):
            tag = f" [hidden in {f.layer}]" if f.hidden else ""
            lines.append(
                f"  [{f.severity}|{f.confidence:.2f}] {f.category}/{f.rule_id}: "
                f"{f.description}{tag}"
            )
            lines.append(f"        -> {f.snippet!r}")
        return "\n".join(lines)

    def explain(self) -> str:
        if not self.findings:
            return ("No injection signals. Still wrap this as data before showing "
                    "it to the model (use cordon.wrap_as_data).")
        parts = [self.summary(), "", "Recommended action:"]
        if self.is_dangerous:
            parts.append("  drop this content or refuse to act on it.")
        elif self.is_suspicious:
            parts.append("  sanitize and wrap as data; do not let it drive tool calls.")
        else:
            parts.append("  wrap as data; treat with mild caution.")
        return "\n".join(parts)

    def to_dict(self) -> dict:
        return {
            "risk": self.risk,
            "is_suspicious": self.is_suspicious,
            "is_dangerous": self.is_dangerous,
            "variants_scanned": self.variants_scanned,
            "categories": self.categories,
            "findings": [
                {
                    "detector": f.detector,
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "description": f.description,
                    "severity": f.severity,
                    "confidence": round(f.confidence, 3),
                    "snippet": f.snippet,
                    "layer": f.layer,
                    "hidden": f.hidden,
                    "start": f.start,
                    "end": f.end,
                }
                for f in self.findings
            ],
        }
