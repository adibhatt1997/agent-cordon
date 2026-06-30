"""Detection rules for agent_cordon.

Each rule is a pattern that commonly appears in prompt-injection or
data-exfiltration attempts embedded in untrusted text. Rules are transparent,
categorized, severity- and confidence-weighted, and easy to extend. They cover
several languages because attackers do not only write in English.

These are heuristics, not proof. agent_cordon is one layer of defense in depth.
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
        "override_everything_es", "instruction_override",
        "Forget/ignore everything (Spanish)", 5, 0.85,
        _c(r"\b(olvida|olvide|olvidar|ignora|ignore|ignorar)\b.{0,20}\b(todo|toda|todas|todos|lo anterior|las anteriores|lo que)\b"),
        lang="es",
    ),
    Rule(
        "instruction_override_hr", "instruction_override",
        "Forget all instructions (Croatian/Serbian)", 5, 0.8,
        _c(r"\bzaboravi\s+sve\b"),
        lang="hr",
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
        "override_everything_de", "instruction_override",
        "Forget/ignore everything or all prior content (German)", 5, 0.85,
        _c(r"\b(vergiss|vergessen sie|ignoriere|ignorieren sie|missachte|l[oö]sche)\b.{0,24}\b(alles|alle|obigen|vorherigen|vorigen|vorangehenden|vorangegangenen|bisherigen)\b|\b(obigen|vorherigen|vorangehenden)\b.{0,30}\b(ignorieren|vergiss|missachte)\b|\bh[oö]re nicht auf\b.{0,24}\b(alles|zuvor|vorher|vorherige)\b|\bsind irrelevant\b"),
        lang="de",
    ),
    Rule(
        "task_switch_de", "instruction_override",
        "Switch to a new task framing (German)", 3, 0.65,
        _c(r"\b(neue|neuen|weitere|weiteren|folgende|folgenden|n[aä]chste)\s+(aufgabe|aufgaben|anweisung|anweisungen|herausforderung)\b|\b(konzentriere|fokussiere)\s+dich\b|\bvon\s+(neu|vorne)\b|\bnun\s+folgen\b|\bfangen\s+sie\s+von\s+vorne\b"),
        lang="de",
    ),
    Rule(
        "persona_injection_de", "role_hijack",
        "Reassigns the model's persona/role (German)", 4, 0.7,
        _c(r"\b(jetzt bist du|nun bist du|du bist (jetzt|nun)|stell dir vor,? du bist|spiele die rolle)\b|\bals \w+ (fungier|agier|auftret)(en|st|t|e)\b|\bich m[oö]chte,? dass (sie|du)\b.{0,24}\bals\b.{0,24}\b(fungier|agier|auftret)"),
        lang="de",
    ),
    Rule(
        "prompt_leak_de", "system_prompt_leak",
        "Asks the model to reveal its prompt (German)", 4, 0.75,
        _c(r"\b(zeige?|zeig|gib|nenne|wiederhole|drucke|verrate)\b.{0,25}\b(prompt|prompt-text|prompt-texte|prompttext|systemnachricht|anweisungen)\b|\bwas\s+(wurde|steht)\b.{0,30}\b(anfang|oben|prompt)\b"),
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

    # --- override / task-switch framing (broad) ---------------------------
    # Catches the very common "forget everything / ignore all the above" and
    # "now focus on your new task" pivots that paraphrase around the precise
    # rule above. Tuned against a public dataset to keep false positives low.
    Rule(
        "override_everything", "instruction_override",
        "Tells the model to forget or ignore everything / all prior content", 5, 0.9,
        _c(r"\b(forget|forgot|ignore|disregard|erase|delete|drop)\b.{0,20}\b(everything|all)\b.{0,24}\b(before|previous|prior|preceding|earlier|above|task|tasks|assignment|assignments|instruction|instructions|order|orders)?\b|\b(forget|forgot|ignore|disregard)\b\s+(everything|all|above|what (i|you) said)\b"),
    ),
    Rule(
        "task_switch", "instruction_override",
        "Frames a switch to a new task/instructions (common injection pivot)", 3, 0.7,
        _c(r"\b(new|next|following|another)\s+(task|tasks|assignment|assignments|instruction|instructions)\b|\b(focus on|concentrate on)\s+(your\s+)?(new\s+)?(task|tasks|assignment)\b|\bstart(ing)?\s+over\b|\bstart\s+from\s+the\s+(front|beginning|top)\b|\bnow\s+(new\s+)?(tasks?|instructions?)\s+(follow|are\s+follow)"),
    ),
    Rule(
        "persona_injection", "role_hijack",
        "Reassigns the model's persona or role (role-play injection)", 4, 0.75,
        _c(r"\b(you are now|now you are|from now on,? you are|pretend (you are|to be|that)|imagine (you are|that you)|i want you to act as|act as an? \w+|(now )?you act as|you (will )?play the (role|part)|you are (a|an|now) \w+ (and|who|that)|role-?playing as|you are role-?playing)\b"),
    ),

    # --- system prompt exfiltration ---------------------------------------
    Rule(
        "reveal_system_prompt", "system_prompt_leak",
        "Asks the model to reveal its system prompt or hidden instructions", 5, 1.0,
        _c(r"\b(reveal|show|print|repeat|output|expose|disclose|tell me|what (are|were))\b.{0,30}\b(system|hidden|initial|original|above|secret)\b.{0,20}\b(prompt|instruction|message|rule)s?\b"),
    ),
    Rule(
        "prompt_leak", "system_prompt_leak",
        "Asks the model to reveal/print its prompt or initial instructions", 4, 0.8,
        _c(r"\b(show|reveal|print|repeat|display|output|list|give me|tell me)\b.{0,25}\b(your |the |all (of )?(your )?)?(prompt|prompts|instruction|instructions|system (message|prompt)|initial (instruction|instructions|prompt))\b|\bwhat (was|is|were)\b.{0,30}\b(written|stated|said)\b.{0,20}\b(beginning|above|prompt|top|start)\b|\bwhat\s+was\s+written\s+at\s+the\s+beginning\b"),
    ),
    Rule(
        "repeat_verbatim", "system_prompt_leak",
        "Asks the model to repeat text verbatim (prompt extraction)", 3, 0.6,
        _c(r"\b(repeat|print|output)\b.{0,20}\b(everything above|all of the above|the text above|verbatim|word for word)\b"),
    ),
    Rule(
        "spellcheck_extract", "system_prompt_leak",
        "Spellcheck/proofread-and-print trick used to extract the prompt", 4, 0.7,
        _c(r"\b(spell\s?check|check the spelling|proof\s?read|correct the spelling)\b.{0,80}\b(print|output|show|repeat|reproduce|display)\b|\b(print|output|show|display)\b.{0,30}\b(the\s+)?(above|preceding|previous|original)\s+(text|prompt|input|instructions?)\b|rechtschreibung.{0,80}(drucken|ausgeben|zeigen)|drucken sie\b.{0,30}(obige|eingabeaufforderung|prompt)"),
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
    Rule(
        "fictional_framing", "jailbreak",
        "Uses a fictional film/role-play scene to smuggle a jailbreak", 3, 0.55,
        _c(r"\b(actors?|characters?|schauspieler)\b.{0,20}\b(in a|in einem)\b.{0,12}\b(film|movie|story|play|scene|geschichte)\b|\bplay(s|ing)?\s+the\s+(leading\s+|main\s+)?(role|part|character)\b|\bstay\s+in\s+character\b|\bspielen\s+die\s+(haupt)?roll?en?\b"),
    ),

    # --- tool / command abuse ---------------------------------------------
    Rule(
        "tool_command_injection", "tool_abuse",
        "Issues direct commands to the agent or its tools", 4, 0.7,
        _c(r"\b(call|invoke|execute|run|use)\b.{0,20}\b(the\s+)?\w+\s+(tool|function|command|api|endpoint)\b|\b(rm\s+-rf|drop\s+table|shutdown|wire transfer|transfer funds|delete all)\b"),
    ),
    Rule(
        "output_manipulation", "tool_abuse",
        "Commands the model to emit attacker-chosen output", 4, 0.7,
        _c(r"\brepeat after me\b|\bjust output\b|\bstop\s*[:\-]\s*write\b|\bstate that\b|\bchange your (instructions?|rules?|prompt|behaviou?r)\b|\boutput\s+[\"“][^\"”]{2,60}[\"”]|\bdo not (answer|look|read)\b.{0,50}\b(just |only )?(output|say|write|respond)\b|\bplease abandon all your\b"),
    ),
    Rule(
        "context_override", "instruction_override",
        "Tells the model to ignore or contradict the provided documents/context", 4, 0.7,
        _c(r"\b(ignore|disregard|forget|do not (look|use|read|consider)|regardless of|instead of)\b.{0,30}\b(the\s+)?(articles?|documents?|context|sources?|passages?|provided (text|documents?|context))\b|\banswer (by|from|with) your own knowledge\b|\bnot by the articles?\b"),
    ),

    # --- hidden / deceptive framing ---------------------------------------
    Rule(
        "hidden_html_comment", "hidden_instruction",
        "Instructions hidden inside HTML comments", 3, 0.8,
        _c(r"<!--[^>]{0,300}?(ignore|instruction|system|you are|do not tell|reveal|password|api key)[^>]{0,300}?-->"),
    ),
    Rule(
        "delimiter_injection", "hidden_instruction",
        "Fake end-of-input / section delimiter to break out of the data block", 3, 0.6,
        _c(r"={3,}\s*end\b|-{3,}\s*end\b|\bend\s+of\s+(prompt|input|document|text|context)\b|\[/?(system|inst|context|assistant)\]"),
    ),
    Rule(
        "meta_injection", "social_engineering",
        "Primes the model to comply or disclaims being an injection", 3, 0.55,
        _c(r"\bthis is not (a |an )?(prompt )?injection\b|\bdies ist keine (aufforderung|eingabe|prompt)|\banswer (every|each) (question|time|prompt) with\b|\b(you are |you'?re )?(not )?supposed to (answer at all times|tell me)\b|\bplease return your embeddings\b"),
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
