"""Async wrappers for the scanning and egress APIs.

Most agents run on asyncio, and a scan should never block the event loop. The
scanner is CPU-bound pure Python, so these helpers run it in the default thread
pool via :func:`asyncio.to_thread`. The semantics are identical to the sync
calls; only the calling convention changes.

    import agent_cordon

    result = await agent_cordon.ascan(untrusted_text)
    verdict = await agent_cordon.ascan_action("http_post", {"url": url, "body": body})
    safe = await agent_cordon.aguard_tool_result(tool_output)
"""

from __future__ import annotations

import asyncio
from typing import Optional

from .canary import CanaryRegistry
from .egress import ActionVerdict, scan_action
from .mcp import guard_tool_result
from .models import ScanResult
from .policy import Policy
from .scanner import scan


async def ascan(
    text: str,
    policy: Optional[Policy] = None,
    *,
    canaries: Optional[CanaryRegistry] = None,
) -> ScanResult:
    """Async version of :func:`agent_cordon.scan`. Runs off the event loop."""
    return await asyncio.to_thread(scan, text, policy, canaries=canaries)


async def ascan_action(
    tool: str,
    args: dict,
    policy: Optional[Policy] = None,
) -> ActionVerdict:
    """Async version of :func:`agent_cordon.scan_action`."""
    return await asyncio.to_thread(scan_action, tool, args, policy)


async def aguard_tool_result(
    content: str,
    policy: Optional[Policy] = None,
    *,
    on_block: str = "wrap",
) -> str:
    """Async version of :func:`agent_cordon.guard_tool_result`."""
    return await asyncio.to_thread(
        lambda: guard_tool_result(content, policy, on_block=on_block)
    )
