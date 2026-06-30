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
| **agent_cordon** | **61.7%** | **100.0%** | **100.0%** | **53.3%** | **61.7%** |

The keyword scanner collapses to **0%** the moment an attacker swaps in Cyrillic
look-alikes, inserts zero-width characters, uses leetspeak, or base64-encodes the
payload — i.e. exactly what real attackers do. agent_cordon normalizes and
recursively decodes first, so the attack is scored on its true content.
Homoglyph and zero-width reach 100% because the *presence* of that obfuscation in
untrusted data is itself a strong signal, which agent_cordon flags directly.

## 2. False positives and latency

| detector | false-positive rate | p50 latency |
|---|---|---|
| keyword/regex (typical) | 1.8% | 0.013 ms |
| **agent_cordon** | **0.0%** | **0.157 ms** |

Both are sub-millisecond. For context, model-based detectors (a fine-tuned
DeBERTa, the common "SOTA" open-source option) typically add **10-100 ms per
scan on CPU**, plus a multi-hundred-MB model download and memory cost. On the hot
path of every tool result and RAG chunk, that is the difference between a guard
you can run on everything and one you ration.

## 3. Egress: a capability the market's injection detectors lack

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
| Plaintext NL recall | model tools: high; keyword tools: low | medium-high (62%), rising |
| **Obfuscated-attack recall** | near 0 (keyword) / degraded (model) | **high** |
| **False-positive rate** | often non-trivial | **0%** measured |
| **Latency** | 10-100 ms (model) | **~0.1 ms** |
| **Dependencies / model** | torch + model, or an API | **none** |
| **Egress / exfiltration** | not addressed | **first-class** |
| **Feedback loop with regression gate** | rare | **yes** |

Honest takeaway: pair agent_cordon with a model verifier (`Policy.verifier`) if
you want the best of both — agent_cordon catches the obfuscated and outbound
cases cheaply and offline, and escalates only the gray-zone natural-language
cases to a heavier model.
