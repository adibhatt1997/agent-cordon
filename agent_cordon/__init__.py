"""agent_cordon: a quarantine line for the data your LLM agent ingests.

agent_cordon inspects untrusted text (web pages, tool results, emails, RAG chunks,
MCP output) for prompt injection BEFORE your agent reads it, sees through
obfuscation (homoglyphs, zero-width/bidi chars, leetspeak, recursive
base64/hex/url/rot13 encoding), and guards outbound actions so your agent
cannot ship secrets to an attacker.

Quickstart:
    import agent_cordon

    r = agent_cordon.scan(untrusted_text)
    if r.is_dangerous:
        ...
    safe = agent_cordon.wrap_as_data(untrusted_text)

    # guard an outbound tool call
    verdict = agent_cordon.scan_action("http_post", {"url": "https://x.com", "body": secret})
    if not verdict:
        ...
"""

from .canary import CanaryRegistry, mint_canary, register_canary
from .egress import ActionVerdict, find_secrets, redact_secrets, scan_action
from .mcp import cordon_tool, guard_tool_result
from .models import Finding, ScanResult
from .policy import DEFAULT_POLICY, Policy, compile_allowlist
from .sanitize import (
    InjectionError,
    Trust,
    build_context,
    guard,
    sanitize,
    spotlight,
    wrap_as_data,
)
from .scanner import scan

__version__ = "0.2.0"
__all__ = [
    # core
    "scan", "ScanResult", "Finding",
    # policy
    "Policy", "DEFAULT_POLICY", "compile_allowlist",
    # sanitize / context
    "sanitize", "spotlight", "wrap_as_data", "build_context", "Trust",
    "guard", "InjectionError",
    # egress firewall
    "scan_action", "ActionVerdict", "find_secrets", "redact_secrets",
    # canaries
    "register_canary", "mint_canary", "CanaryRegistry",
    # mcp
    "guard_tool_result", "cordon_tool",
    "__version__",
]
