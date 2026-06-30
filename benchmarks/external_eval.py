"""Evaluate agent_cordon against a *public, third-party* prompt-injection dataset.

The bundled corpus (corpus.jsonl) is small and authored alongside the rules, so
it cannot prove the detector generalizes. This script pulls a public dataset and
reports the same metrics on data agent_cordon has never seen.

Default dataset: ``deepset/prompt-injections`` (label 1 = injection, 0 = benign),
fetched over the Hugging Face datasets-server REST API using only the standard
library (no extra dependencies, no auth). Results are cached under
``benchmarks/.cache/`` so reruns are offline.

    python benchmarks/external_eval.py
    python benchmarks/external_eval.py --strict
    python benchmarks/external_eval.py --dataset deepset/prompt-injections --split test

Network is only needed the first time (to download and cache the rows).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import agent_cordon  # noqa: E402
from run_benchmark import evaluate  # noqa: E402

_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
_DS_API = "https://datasets-server.huggingface.co/rows"


def _cache_path(dataset: str, split: str) -> str:
    safe = dataset.replace("/", "__")
    return os.path.join(_CACHE_DIR, f"{safe}.{split}.jsonl")


def _fetch_page(dataset: str, split: str, offset: int, length: int) -> dict:
    qs = urllib.parse.urlencode({
        "dataset": dataset, "config": "default", "split": split,
        "offset": offset, "length": length,
    })
    req = urllib.request.Request(f"{_DS_API}?{qs}", headers={"User-Agent": "agent_cordon-eval"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (fixed https host)
        return json.loads(resp.read().decode("utf-8"))


def download(dataset: str, split: str) -> list[dict]:
    """Download and cache a split, normalized to {text, label} rows."""
    path = _cache_path(dataset, split)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    os.makedirs(_CACHE_DIR, exist_ok=True)
    rows: list[dict] = []
    offset, length = 0, 100
    total = None
    while total is None or offset < total:
        for attempt in range(4):
            try:
                page = _fetch_page(dataset, split, offset, length)
                break
            except Exception as e:  # transient network: back off and retry
                if attempt == 3:
                    raise
                time.sleep(1.5 * (attempt + 1))
                print(f"  retry {attempt + 1} at offset {offset}: {e}", file=sys.stderr)
        total = page.get("num_rows_total", 0)
        page_rows = page.get("rows", [])
        if not page_rows:
            break
        for item in page_rows:
            r = item.get("row", {})
            text = r.get("text")
            label = r.get("label")
            if text is None or label is None:
                continue
            rows.append({"text": text, "label": "attack" if int(label) == 1 else "benign"})
        offset += length

    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="deepset/prompt-injections")
    ap.add_argument("--split", default="test", help="train or test")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--lenient", action="store_true")
    args = ap.parse_args()

    if args.strict:
        policy = agent_cordon.Policy.strict()
        preset = "strict"
    elif args.lenient:
        policy = agent_cordon.Policy.lenient()
        preset = "lenient"
    else:
        policy = None
        preset = "default"

    print(f"downloading {args.dataset} [{args.split}] ...", file=sys.stderr)
    rows = download(args.dataset, args.split)
    if not rows:
        print("no rows fetched", file=sys.stderr)
        return 1

    m = evaluate(rows, policy)
    c = m["counts"]
    print(f"\nexternal benchmark: {args.dataset} [{args.split}]  (policy: {preset})")
    print(f"  samples: {len(rows)}  ({c['tp'] + c['fn']} attacks, {c['tn'] + c['fp']} benign)")
    print("-" * 56)
    print(f"  detection rate (recall): {m['recall']*100:5.1f}%   (tp={c['tp']} fn={c['fn']})")
    print(f"  false-positive rate:     {m['false_positive_rate']*100:5.1f}%   (fp={c['fp']} tn={c['tn']})")
    print(f"  precision:               {m['precision']*100:5.1f}%")
    print(f"  accuracy:                {m['accuracy']*100:5.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
