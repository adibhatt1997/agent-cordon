"""Detection rules for agentward.

Each rule is a pattern that commonly appears in prompt-injection or
data-exfiltration attempts embedded in untrusted text. Rules are transparent,
categorized, severity- and confidence-weighted, and easy to extend. They cover
several languages because attackers do not only write in English.

These are heuristics, not proof. agentward is one layer of defense in depth.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    description: str
    severity: int       # 1 (low) .. 5 (critical)
    confidence: float   # 0..1 base confidence for a match
    pattern: "re.Pattern[str]"
    lang: str = "en"


def _c(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.IGNORECASE)


RULES: list[Rule] = [
    # --- instruction override ---------------------------------------------
    Rule(
        "instruction_override", "instruction_override",
        "Attempts to override or erase prior instructions", 5, 1.0,
        _c(r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(previous|prior|above|earlier|all|any|your)\b.{0,30}\b(instruction|prompt|message|rule|context|direction|guideline)s?\b"),
    ),
    Rule(
        "instruction_override_es", "instruction_override",
        "Instruction override (Spanish)", 5, 0.9,
        _c(r"\b(ignora|olvida|descarta)\b.{0,30}\b(instrucciones|indicaciones|reglas)\b.{0,20}\b(anteriores|previas|todas)\b"),
        lang="es",
    ),
    Rule(
        "instruction_override_fr", "instruction_override",
        "Instruction override (French)", 5, 0.9,
        _c(r"\b(ignorez|ignore|oubliez|oublie)\b.{0,30}\b(instructions|consignes|r[eè]gles)\b.{0,20}\b(pr[eé]c[eé]dentes|ant[eé]rieures)\b"),
        lang="fr",
    ),
    Rule(
        "instruction_override_de", "instruction_override",
        "Instruction override (German)", 5, 0.9,
        _c(r"\b(ignoriere|vergiss|missachte)\b.{0,30}\b(vorherigen|vorigen|bisherigen|alle)\b.{0,20}\b(anweisungen|anweisung|regeln)\b"),
        lang="de",
    ),
    Rule(
        "instruction_override_ru", "instruction_override",
        "Instruction override (Russian)", 5, 0.9,
        _c(r"(игнорируй|забудь|не\s+обращай\s+внимания).{0,30}(предыдущие|все|твои).{0,20}(инструкции|указания|правила)"),
        lang="ru",
    ),
    Rule(
        "instruction_override_zh", "instruction_override",
        "Instruction override (Chinese)", 5, 0.9,
        _c(r"(忽略|无视|忘记).{0,8}(之前|上述|所有|先前).{0,8}(指令|指示|规则|提示)"),
        lang="zh",
    ),

    # --- system prompt exfiltration ---------------------------------------
    Rule(
        "reveal_system_prompt", "system_prompt_leak",
        "Asks the model to reveal its system prompt or hidden instructions", 5, 1.0,
        _c(r"\b(reveal|show|print|repeat|output|expose|disclose|tell me|what (are|were))\b.{0,30}\b(system|hidden|initial|original|above|secret)\b.{0,20}\b(prompt|instruction|message|rule)s?\b"),
    ),
    Rule(
        "repeat_verbatim", "system_prompt_leak",
        "Asks the model to repeat text verbatim (prompt extraction)", 3, 0.6,
        _c(r"\b(repeat|print|output)\b.{0,20}\b(everything above|all of the above|the text above|verbatim|word for word)\b"),
    ),

    # --- secret / credential exfiltration ---------------------------------
    Rule(
        "secret_exfiltration", "exfiltration",
        "Tries to make the agent leak secrets, keys, or credentials", 5, 1.0,
        _c(r"\b(api[_ ]?key|secret|password|passwd|token|credential|private[_ ]?key|\.env|access[_ ]?key)\b.{0,40}\b(send|post|email|exfiltrat|upload|reveal|share|print|leak|forward)\b|\b(send|post|email|exfiltrat|upload|forward|leak)\b.{0,40}\b(api[_ ]?key|secret|password|token|credential)s?\b"),
    ),
    Rule(
        "data_exfiltration_url", "exfiltration",
        "Embedded instruction to send data to an external URL", 4, 0.85,
        _c(r"\b(send|post|forward|upload|transmit|exfiltrate|leak)\b.{0,40}\bhttps?://"),
    ),
    Rule(
        "markdown_image_exfil", "exfiltration",
        "Markdown image whose URL could smuggle data out", 4, 0.8,
        _c(r"!\[[^\]]*\]\(https?://[^)]*[?&=][^)]*\)"),
    ),

    # --- role hijack / jailbreak ------------------------------------------
    Rule(
        "role_hijack", "role_hijack",
        "Tries to reassign the model's role or identity", 4, 0.8,
        _c(r"\byou are now\b|\bfrom now on,? you\b|\bact as\b.{0,40}\b(jailbreak|unfiltered|no restrictions|DAN|uncensored)\b|\bnew (system )?(role|persona|instruction)s?\b\s*:"),
    ),
    Rule(
        "jailbreak_phrase", "jailbreak",
        "Known jailbreak framing", 3, 0.7,
        _c(r"\b(DAN|do anything now|developer mode|jailbreak|without any (restrictions|filter|guidelines)|pretend you have no|ignore your (guidelines|safety))\b"),
    ),

    # --- tool / command abuse ---------------------------------------------
    Rule(
        "tool_command_injection", "tool_abuse",
        "Issues direct commands to the agent or its tools", 4, 0.7,
        _c(r"\b(call|invoke|execute|run|use)\b.{0,20}\b(the\s+)?\w+\s+(tool|function|command|api|endpoint)\b|\b(rm\s+-rf|drop\s+table|shutdown|wire transfer|transfer funds|delete all)\b"),
    ),

    # --- hidden / deceptive framing ---------------------------------------
    Rule(
        "hidden_html_comment", "hidden_instruction",
        "Instructions hidden inside HTML comments", 3, 0.8,
        _c(r"<!--[^>]{0,300}?(ignore|instruction|system|you are|do not tell|reveal|password|api key)[^>]{0,300}?-->"),
    ),
    Rule(
        "fake_authority", "social_engineering",
        "Impersonates the developer, system, or admin to gain trust", 3, 0.7,
        _c(r"\b(as|this is)\b.{0,15}\b(the\s+)?(system|developer|administrator|admin|openai|anthropic|your (creator|owner))\b.{0,25}\b(instruct|require|command|tell you|order|demand)"),
    ),
    Rule(
        "urgent_compliance", "social_engineering",
        "Pressures the model to comply immediately and silently", 3, 0.6,
        _c(r"\b(do not (tell|inform|alert|mention|notify)|without (telling|informing|asking|notifying)|silently|secretly|covertly)\b.{0,30}\b(user|human|owner|operator)\b"),
    ),
]


# Chat/role markers that should never appear inside external *data*.
ROLE_MARKER_RE = re.compile(
    r"(<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[INST\]|\[/INST\]|<<SYS>>|"
    r"^\s*###\s*(system|assistant|instruction)\b|"
    r"^\s*(system|assistant)\s*:)",
    re.IGNORECASE | re.MULTILINE,
)
