# Contributing to agent_cordon

Thanks for helping make agents safer. `agent_cordon` is meant to be community-owned.

## The most valuable contributions

1. **New injection patterns seen in the wild.** Add a `Rule` to
   `agent_cordon/rules.py` and a test that proves it fires. Real attacks, multilingual
   payloads, and novel obfuscations are gold.
2. **Fewer false positives.** If benign text trips a rule, tighten the pattern
   or add an allowlist example, and add a test that locks in the fix.
3. **New detectors or secret shapes.** See the extension points in
   [ARCHITECTURE.md](ARCHITECTURE.md).

## Dev setup

```bash
git clone https://github.com/adibhatt1997/agent-cordon
cd agent_cordon
pip install -e ".[dev]"
pytest
```

## Adding a rule

```python
Rule(
    "my_rule_id", "category_name",
    "Short human description", severity=4, confidence=0.8,
    _c(r"your\s+regex"), lang="en",
)
```

- `severity` 1..5, `confidence` 0..1.
- Reuse an existing `category` where possible so scoring stays consistent.
- Always add at least one positive test and, if there is plausible overlap with
  normal text, one negative test.

## Pull request checklist

- [ ] `pytest` passes.
- [ ] New behavior has tests.
- [ ] No new runtime dependencies (agent_cordon is zero-dependency by design).
- [ ] Public API changes are reflected in the README.

## Reporting a vulnerability

If you find a bypass, please open an issue with a minimal reproduction. A bypass
plus a failing test is the ideal report, and usually the fastest fix.

## Code of conduct

Be kind and constructive. We are all here to make AI agents harder to hijack.
