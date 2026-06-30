"""Benchmark cordon against a labeled corpus of attacks and benign text.

Reports detection rate (recall on attacks), false-positive rate (on benign),
precision, and accuracy, plus a per-family breakdown.

    python benchmarks/run_benchmark.py
    python benchmarks/run_benchmark.py --strict
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# allow running from anywhere
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import cordon  # noqa: E402

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus.jsonl")


def load_corpus(path: str = CORPUS) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def evaluate(rows: list[dict], policy=None) -> dict:
    tp = fp = tn = fn = 0
    missed: list[str] = []
    false_alarms: list[str] = []
    by_family: dict[str, list[int]] = {}

    for row in rows:
        flagged = cordon.scan(row["text"], policy).is_suspicious
        is_attack = row["label"] == "attack"
        fam = row.get("family", "?")
        by_family.setdefault(fam, [0, 0])
        if is_attack:
            by_family[fam][1] += 1
            if flagged:
                tp += 1
                by_family[fam][0] += 1
            else:
                fn += 1
                missed.append(row["text"])
        else:
            if flagged:
                fp += 1
                false_alarms.append(row["text"])
            else:
                tn += 1

    attacks = tp + fn
    benign = tn + fp
    return {
        "recall": tp / attacks if attacks else 0.0,
        "false_positive_rate": fp / benign if benign else 0.0,
        "precision": tp / (tp + fp) if (tp + fp) else 0.0,
        "accuracy": (tp + tn) / len(rows) if rows else 0.0,
        "counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "by_family": by_family,
        "missed": missed,
        "false_alarms": false_alarms,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()
    policy = cordon.Policy.strict() if args.strict else None

    rows = load_corpus()
    m = evaluate(rows, policy)

    print(f"cordon benchmark  ({len(rows)} samples, "
          f"{m['counts']['tp'] + m['counts']['fn']} attacks, "
          f"{m['counts']['tn'] + m['counts']['fp']} benign)")
    print("-" * 52)
    print(f"  detection rate (recall): {m['recall']*100:5.1f}%")
    print(f"  false-positive rate:     {m['false_positive_rate']*100:5.1f}%")
    print(f"  precision:               {m['precision']*100:5.1f}%")
    print(f"  accuracy:                {m['accuracy']*100:5.1f}%")
    print("-" * 52)
    print("  by attack family (detected / total):")
    for fam, (hit, tot) in sorted(m["by_family"].items()):
        if tot:
            print(f"    {fam:14s} {hit}/{tot}")
    if m["missed"]:
        print("\n  missed attacks:")
        for t in m["missed"]:
            print(f"    - {t[:70]}")
    if m["false_alarms"]:
        print("\n  false alarms:")
        for t in m["false_alarms"]:
            print(f"    - {t[:70]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
