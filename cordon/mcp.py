"""MCP-native helpers.

The most common modern injection vector is an MCP tool returning attacker
text that flows straight into the agent's context. These helpers put a cordon
on that boundary with almost no code change.
"""

from __future__ import annotations

import functools
from typing import Callable, Optional

from .policy import Policy
from .sanitize import InjectionError, wrap_as_data
from .scanner import scan


def guard_tool_result(
    text: str,
    policy: Optional[Policy] = None,
    *,
    on_block: str = "wrap",   # "wrap" | "sanitize" | "raise" | "drop"
) -> str:
    """Run a single MCP/tool result through cordon and return safe content.

    - "wrap":     always wrap as data (recommended default)
    - "sanitize": wrap, and additionally mark/strip detected injections
    - "raise":    raise InjectionError if dangerous
    - "drop":     replace dangerous content with a short placeholder
    """
    result = scan(text, policy)
    if on_block == "raise" and result.is_dangerous:
        raise InjectionError(result)
    if on_block == "drop" and result.is_dangerous:
        return f"[cordon dropped tool output: risk {result.risk}/100, {', '.join(result.categories)}]"
    if on_block == "sanitize":
        from .sanitize import sanitize as _san
        return wrap_as_data(_san(text, result))
    return wrap_as_data(text)


def cordon_tool(
    func: Optional[Callable] = None,
    *,
    policy: Optional[Policy] = None,
    on_block: str = "wrap",
):
    """Decorator for an MCP tool handler whose return value is text.

    Wraps the returned string with guard_tool_result so every result is
    inspected and neutralized before it reaches the model.

        @cordon_tool(on_block="drop")
        def read_url(url: str) -> str:
            ...
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            out = fn(*args, **kwargs)
            if isinstance(out, str):
                return guard_tool_result(out, policy, on_block=on_block)
            return out
        return wrapper

    if func is not None:
        return decorator(func)
    return decorator
