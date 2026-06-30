"""Egress firewall: guard the actions your agent is about to take.

Input scanning is half the battle. The damage usually happens on the way OUT:
the agent makes a tool call that ships secrets to an attacker's URL, or posts
your data somewhere it should not go. agent_cordon inspects the outbound action
before it executes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .policy import DEFAULT_POLICY, Policy

# Common secret shapes. Conservative, low false positive.
SECRET_PATTERNS = {
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "assigned_secret": re.compile(
        r"(?i)\b(api[_-]?key|secret|access[_-]?token|password|passwd)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
}

_URL_RE = re.compile(r"https?://[^\s'\"<>)]+")


@dataclass
class ActionVerdict:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    secrets_found: list[str] = field(default_factory=list)
    destinations: list[str] = field(default_factory=list)
    redacted_args: dict | None = None

    def __bool__(self) -> bool:
        return self.allowed

    def summary(self) -> str:
        head = "ALLOW" if self.allowed else "BLOCK"
        out = [f"{head} action"]
        for r in self.reasons:
            out.append(f"  - {r}")
        return "\n".join(out)


def find_secrets(text: str) -> list[str]:
    found = []
    for name, pat in SECRET_PATTERNS.items():
        if pat.search(text):
            found.append(name)
    return found


def redact_secrets(text: str) -> str:
    for name, pat in SECRET_PATTERNS.items():
        text = pat.sub(f"[REDACTED:{name}]", text)
    return text


def _domain_allowed(host: str, policy: Policy) -> bool:
    host = host.lower()
    if any(host == d or host.endswith("." + d) for d in policy.blocked_domains):
        return False
    if policy.allowed_domains:
        return any(host == d or host.endswith("." + d) for d in policy.allowed_domains)
    return True


def _flatten(args) -> str:
    if isinstance(args, str):
        return args
    if isinstance(args, dict):
        return " ".join(f"{k}={_flatten(v)}" for k, v in args.items())
    if isinstance(args, (list, tuple)):
        return " ".join(_flatten(v) for v in args)
    return str(args)


def scan_action(
    tool_name: str,
    args,
    policy: Policy | None = None,
    *,
    redact: bool = True,
) -> ActionVerdict:
    """Decide whether an outbound tool call is safe to execute.

    Blocks when secrets are headed to a disallowed destination, or when any
    destination is explicitly blocked. Optionally returns redacted args so a
    borderline call can proceed without leaking the secret value.
    """
    policy = policy or DEFAULT_POLICY
    blob = _flatten(args)

    secrets = find_secrets(blob)
    urls = _URL_RE.findall(blob)
    hosts = [urlparse(u).hostname or "" for u in urls]

    reasons: list[str] = []
    allowed = True

    for h in hosts:
        if h and not _domain_allowed(h, policy):
            allowed = False
            reasons.append(f"destination '{h}' is not allowed by policy")

    egressy = bool(urls) or re.search(
        r"(http|fetch|post|send|email|webhook|upload|curl|request|publish)",
        tool_name, re.IGNORECASE)

    if secrets and egressy:
        # Secrets leaving via a network-shaped tool is the classic exfil.
        if any(h and not _domain_allowed(h, policy) for h in hosts) or not policy.allowed_domains:
            allowed = False
        reasons.append(
            f"outbound call '{tool_name}' carries secret-like data: {', '.join(secrets)}")

    redacted = None
    if redact and secrets and isinstance(args, dict):
        redacted = {k: redact_secrets(_flatten(v)) for k, v in args.items()}

    if allowed and not reasons:
        reasons.append("no exfiltration signals detected")

    return ActionVerdict(
        allowed=allowed, reasons=reasons, secrets_found=secrets,
        destinations=[h for h in hosts if h], redacted_args=redacted,
    )
