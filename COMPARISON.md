# Where agent_cordon beats what is on the market

This is the honest version. A zero-dependency heuristic does **not** beat a
fine-tuned transformer at raw natural-language recall, and we do not claim it
does. It wins decisively on the axes that actually decide whether a guard is
usable in production: **evasion robustness, latency, footprint, and egress** —
the last of which most injection detectors do not address at all.

Reproduce everything here with:

```bash
python benchmarks/compare.py
```

Baseline = a generous keyword/regex blocklist (case-insensitive, 40+ phrases),
standing in for the "typical scanner." Dataset = the held-out
`deepset/prompt-injections` test split (60 attacks, 56 benign).

## 1. Evasion: detection rate (recall) by obfuscation

| detector | plaintext | homoglyph | zero-width | leetspeak | base64 |
|---|---|---|---|---|---|
| keyword/regex (typical) | 25.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| **agent_cordon** | **53.3%** | **100.0%** | **100.0%** | **45.0%** | **61.7%** |

The keyword scanner collapses to **0%** the moment an attacker swaps in Cyrillic
look-alikes, inserts zero-width characters, uses leetspeak, or base64-encodes the
payload — i.e. exactly what real attackers do. agent_cordon normalizes and
recursively decodes first, so the attack is scored on its true content.
Homoglyph and zero-width reach 100% because the *presence* of that obfuscation in
untrusted data is itself a strong signal, which agent_cordon flags directly.

## 2. Precision and false positives across independent datasets

Measured on three public datasets (only the deepset *train* split was ever used
for tuning; the rest are untouched):

| dataset | recall | false-positive rate | precision |
|---|---|---|---|
| deepset/prompt-injections (test) | 53.3% | 0.0% | 100.0% |
| jackhhao/jailbreak-classification (untuned) | 61.9% | 2.4% | 96.6% |
| xTRam1/safe-guard-prompt-injection (untuned) | 31.2% | 0.8% | 94.9% |

**95-100% precision** across all three: when agent_cordon flags something, it is
almost always right. Role-play framing ("act as a...") is treated as a
*corroborating* signal, not a standalone trigger, precisely so legitimate
persona prompts do not become false positives.

## 3. Latency

Per-scan p50 latency is **well under a millisecond** (roughly 0.02 ms for the
keyword baseline and ~0.1-0.2 ms for agent_cordon; absolute numbers are
machine-dependent, run `benchmarks/compare.py` on yours). For context,
model-based detectors (a fine-tuned DeBERTa, the common open-source option)
typically add **10-100 ms per scan on CPU**, plus a multi-hundred-MB model
download and memory cost. On the hot path of every tool result and RAG chunk,
that is the difference between a guard you run on everything and one you ration.

## 4. Egress: a capability the market's injection detectors lack

Prompt-injection detectors classify *input*. They have no concept of the action
an agent is about to take, so they cannot stop the actual exfiltration step.

```
secret -> unapproved domain (http_post to evil.tld with an AWS/API key in the body)
  keyword/regex (typical):  no concept of outbound actions  -> MISS
  agent_cordon:             BLOCKED (destination 'evil.tld' is not allowed by policy)
```

## Summary

| dimension | typical market tool | agent_cordon |
|---|---|---|
| Plaintext NL recall | model tools: high; keyword tools: low | medium (31-62%), rising |
| **Obfuscated-attack recall** | near 0 (keyword) / degraded (model) | **high (45-100%)** |
| **Precision** | varies | **95-100%** across 3 sets |
| **False-positive rate** | often non-trivial | **0-2.4%** measured |
| **Latency** | 10-100 ms (model) | **~0.1 ms** |
| **Dependencies / model** | torch + model, or an API | **none** |
| **Egress / exfiltration** | not addressed | **first-class** |
| **Feedback loop with regression gate** | rare | **yes** |

Honest takeaway: pair agent_cordon with a model verifier (`Policy.verifier`) if
you want the best of both — agent_cordon catches the obfuscated and outbound
cases cheaply and offline, and escalates only the gray-zone natural-language
cases to a heavier model.
