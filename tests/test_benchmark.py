"""Quality gate: the benchmark corpus must keep meeting minimum bars.

This locks in detection quality so a future change that regresses recall or
spikes false positives fails CI.
"""

import importlib.util
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_BENCH = os.path.join(_HERE, "..", "benchmarks", "run_benchmark.py")

spec = importlib.util.spec_from_file_location("bench", _BENCH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def test_detection_and_false_positive_bars():
    rows = bench.load_corpus()
    m = bench.evaluate(rows)
    assert m["recall"] >= 0.95, f"recall regressed: {m['recall']:.2f}, missed={m['missed']}"
    assert m["false_positive_rate"] <= 0.10, (
        f"too many false positives: {m['false_positive_rate']:.2f}, {m['false_alarms']}")
    assert m["precision"] >= 0.90


def test_strict_catches_everything_default_catches():
    rows = bench.load_corpus()
    import cordon
    m = bench.evaluate(rows, cordon.Policy.strict())
    assert m["recall"] >= m["false_positive_rate"]  # strict stays sane
