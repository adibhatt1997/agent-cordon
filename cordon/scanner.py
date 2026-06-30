"""The cordon scanning engine.

Pipeline:
    text
      -> build variants (raw, canonical, de-leet, base64/hex/url/rot13 decoded)
      -> run every detector over every variant
      -> run canary tripwires
      -> de-duplicate, drop allowlisted / low-confidence noise
      -> severity x confidence scoring with multi-vector bonus
      -> optional second-stage verifier for gray-zone content
      -> ScanResult
"""

from __future__ import annotations

from typing import Optional

from .canary import CanaryRegistry, default_registry
from .detectors import (
    ObfuscationDetector,
    PatternDetector,
    RoleMarkerDetector,
    StructuralDetector,
)
from .models import Finding, ScanResult
from .normalize import build_variants, canonical
from .policy import DEFAULT_POLICY, Policy
from .rules import RULES

_SEVERITY_WEIGHT = {1: 5, 2: 10, 3: 18, 4: 30, 5: 45}


def _with_conf(f: Finding, conf: float) -> Finding:
    return Finding(
        detector=f.detector, rule_id=f.rule_id, category=f.category,
        description=f.description, severity=f.severity, confidence=conf,
        snippet=f.snippet, layer=f.layer, start=f.start, end=f.end,
    )


def _score(findings: list[Finding]) -> int:
    if not findings:
        return 0
    weight = sum(_SEVERITY_WEIGHT[f.severity] * f.confidence for f in findings)
    # Multi-vector bonus: independent attack categories are more convincing.
    distinct = len({f.category for f in findings})
    weight += max(0, distinct - 1) * 5
    risk = 100 * (1 - 1 / (1 + weight / 30))
    return int(round(min(risk, 100)))


def _dedupe(findings: list[Finding]) -> list[Finding]:
    best: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.category, f.snippet.strip().lower()[:80])
        cur = best.get(key)
        if cur is None or (f.severity, f.confidence) > (cur.severity, cur.confidence):
            best[key] = f
    return list(best.values())


def scan(
    text: str,
    policy: Optional[Policy] = None,
    *,
    canaries: Optional[CanaryRegistry] = None,
) -> ScanResult:
    """Scan untrusted text for prompt-injection / exfiltration / obfuscation.

    Heuristic, layered defense. Returns a ScanResult with a 0..100 risk score.
    """
    if text is None:
        raise TypeError("scan() expects a string, got None")
    policy = policy or DEFAULT_POLICY
    canaries = canaries if canaries is not None else default_registry

    pattern = PatternDetector(list(RULES) + list(policy.extra_rules))
    variant_detectors = [pattern]
    if policy.enable_role_markers:
        variant_detectors.append(RoleMarkerDetector())
    if policy.enable_structural:
        variant_detectors.append(StructuralDetector())

    variants = build_variants(
        text,
        enable_confusables=policy.enable_confusables,
        enable_deleet=policy.enable_deleet,
        enable_decoding=policy.enable_decoding,
        max_decode_depth=policy.max_decode_depth,
    )

    raw_findings: list[Finding] = []
    for v in variants:
        for det in variant_detectors:
            for f in det.detect(v.text, v.label):
                conf = f.confidence * v.confidence
                if v.derived:                       # hidden payloads are a stronger signal
                    conf = min(1.0, conf * 1.15)
                raw_findings.append(_with_conf(f, conf))

    # obfuscation + canaries run on the raw text
    raw_findings.extend(ObfuscationDetector().detect(text, "raw"))
    raw_findings.extend(canaries.scan(text, "raw"))

    # noise control
    filtered = [
        f for f in raw_findings
        if f.confidence >= policy.min_confidence and not policy.allowlisted(f.snippet)
    ]
    findings = _dedupe(filtered)
    findings.sort(key=lambda x: (-x.severity, -x.confidence))

    risk = _score(findings)

    # optional second-stage verifier for gray-zone content
    lo, hi = policy.verify_band
    if policy.verifier is not None and lo <= risk < hi:
        try:
            v_risk = float(policy.verifier(canonical(text)))
            v_risk = max(0.0, min(1.0, v_risk)) * 100
            risk = int(round(0.5 * risk + 0.5 * v_risk))  # blend heuristic + verifier
        except Exception:
            pass  # verifier must never break the scan

    result = ScanResult(
        text=text, normalized=canonical(text), findings=findings, risk=risk,
        variants_scanned=len(variants),
        suspicious_threshold=policy.suspicious_threshold,
        dangerous_threshold=policy.dangerous_threshold,
    )

    if policy.on_event is not None:
        try:
            policy.on_event(result)
        except Exception:
            pass
    return result
