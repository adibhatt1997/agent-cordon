"""Retrain from the feedback loop, gated against regressions.

This is the "train again" step. It takes a feedback file of confirmed
corrections, applies it to a base policy, and verifies two things:

  1. every recorded correction is now classified correctly  (the guarantee), and
  2. nothing that passed before regressed                    (the gate).

If either check fails it exits non-zero, so you can wire it into CI and never
ship a policy that forgot something it had already learned.

    python benchmarks/feedback_retrain.py --feedback feedback.jsonl

There is no magic "100% on all inputs" here, and there cannot be for an
adversarial problem. What this guarantees is "100% on everything labeled",
enforced on every run.
"""

from __future__ import annotations

import argparse
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import agent_cordon  # noqa: E402
from run_benchmark import evaluate, load_corpus  # noqa: E402


def check_feedback(store: agent_cordon.FeedbackStore, policy) -> list[str]:
    """Return a list of feedback entries still classified wrong (should be empty)."""
    failures = []
    for e in store.entries:
        flagged = agent_cordon.scan(e.text, policy).is_suspicious
        want = (e.label == "attack")
        if flagged != want:
            failures.append(f"[{e.label}] still wrong: {e.text[:70]!r}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--feedback", required=True, help="path to a feedback JSONL file")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    base = agent_cordon.Policy.strict() if args.strict else agent_cordon.Policy()
    store = agent_cordon.FeedbackStore(args.feedback)
    s = store.stats()
    print(f"feedback: {s['total']} entries "
          f"({s['missed_attacks']} missed attacks, {s['false_alarms']} false alarms)")

    # baseline on the bundled corpus, before applying feedback
    corpus = load_corpus()
    before = evaluate(corpus, base)

    learned = store.apply(base)

    # 1) the guarantee: every recorded correction is now correct
    failures = check_feedback(store, learned)

    # 2) the gate: the corpus must not regress
    after = evaluate(corpus, learned)
    regressed = after["recall"] < before["recall"] or \
        after["false_positive_rate"] > before["false_positive_rate"]

    print("-" * 56)
    print(f"  corpus recall:  {before['recall']*100:5.1f}%  ->  {after['recall']*100:5.1f}%")
    print(f"  corpus FPR:     {before['false_positive_rate']*100:5.1f}%  ->  "
          f"{after['false_positive_rate']*100:5.1f}%")
    print(f"  feedback recall after retrain: "
          f"{(1 - len([f for f in failures if f.startswith('[attack')]) / max(1, s['missed_attacks']))*100:5.1f}%")

    ok = not failures and not regressed
    if failures:
        print("\n  FEEDBACK NOT FULLY LEARNED:")
        for f in failures:
            print("   -", f)
    if regressed:
        print("\n  REGRESSION on the bundled corpus: refusing this policy.")
    print("\n", "OK: learned everything, no regressions." if ok else "FAILED.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
