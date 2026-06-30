"""Canary tokens and secret tripwires.

Register strings that should NEVER appear in untrusted input or outbound
payloads: your real system-prompt signature, a unique canary you seeded into
the context, or actual secrets. If agent_cordon sees one cross the boundary, that is
an extraction or exfiltration attempt, not a coincidence.
"""

from __future__ import annotations

import secrets as _secrets
from dataclasses import dataclass, field

from .models import Finding
from .normalize import canonical


@dataclass
class CanaryRegistry:
    tokens: dict[str, str] = field(default_factory=dict)  # value -> label

    def register(self, value: str, label: str = "canary") -> str:
        """Register an existing secret/signature to watch for. Returns the value."""
        if value:
            self.tokens[value] = label
        return value

    def mint(self, label: str = "canary") -> str:
        """Create a fresh unguessable canary, register it, and return it.

        Seed the returned token into your system prompt or context. If it ever
        shows up in tool output, the model is being induced to leak context.
        """
        token = "agent_cordon-" + _secrets.token_hex(8)
        self.tokens[token] = label
        return token

    def scan(self, text: str, layer: str = "raw") -> list[Finding]:
        if not self.tokens or not text:
            return []
        hay = canonical(text)
        out: list[Finding] = []
        for value, label in self.tokens.items():
            if value and (value in text or value in hay):
                idx = text.find(value)
                out.append(Finding(
                    detector="canary", rule_id=f"canary:{label}", category="canary_leak",
                    description=f"Registered canary/secret '{label}' appeared in this content",
                    severity=5, confidence=1.0,
                    snippet=value[:12] + "..." if len(value) > 12 else value,
                    layer=layer, start=idx, end=idx + len(value) if idx >= 0 else -1,
                ))
        return out


# A process-wide default registry for convenience.
default_registry = CanaryRegistry()


def register_canary(value: str, label: str = "canary") -> str:
    return default_registry.register(value, label)


def mint_canary(label: str = "canary") -> str:
    return default_registry.mint(label)
