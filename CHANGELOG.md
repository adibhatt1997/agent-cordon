# Changelog

All notable changes to agent_cordon are documented here. Format roughly follows
Keep a Changelog; this project uses semantic versioning.

## [0.3.0]

Hardening, honest evaluation, and a feedback loop.

### Added
- **Feedback loop** (`FeedbackStore`): record a missed attack or a false alarm
  and the loop guarantees that exact case (and cosmetic variants) is classified
  correctly on every future scan. `Policy.exact_attack` / `Policy.exact_benign`
  carry the learned signatures; `benchmarks/feedback_retrain.py` re-applies them
  and gates against regressions.
- **Async API**: `ascan`, `ascan_action`, `aguard_tool_result` run the scan off
  the event loop via `asyncio.to_thread`.
- **Denial-of-service hardening**: input length cap (`max_input_chars`) plus
  decode-bomb limits (`max_decode_variants`, `max_blob_chars`) and bounded
  recursion, so scanning attacker-controlled text stays fast and predictable.
- **Config loading** with zero dependencies: `Policy.from_env`,
  `Policy.from_file` (JSON), and `Policy.from_mapping`.
- **External benchmark** (`benchmarks/external_eval.py`): evaluates against the
  public `deepset/prompt-injections` dataset over the standard library, and the
  benchmark now reports per-scan latency (p50/p95/mean).
- Broadened, tuned detection rules (override/task-switch/persona/prompt-leak/
  context-override/output-manipulation families, English + German + Spanish +
  Croatian), lifting held-out recall on the deepset test split from ~10% to
  ~53% at a 0% false-positive rate. Role-play framing is a corroborating signal,
  not a standalone trigger, to keep precision high (95-100% across three
  independent public datasets).
- `examples/structured_logging.py` for the telemetry hook.

### Notes
- Still zero runtime dependencies. No external model or API is ever called.

## [0.2.0]

The advanced engine. Renamed from the original prototype to `agent_cordon`.

### Changed
- Renamed the import package to `agent_cordon`, the distribution to
  `agent_cordon`, and the console commands to `agent-cordon` and
  `agent-cordon-mcp`. Update imports (`import agent_cordon`) and any scripts
  accordingly. The `cordon_tool` decorator keeps its name.

### Added
- Variant pipeline: NFKC normalization, unicode confusable/homoglyph folding,
  zero-width and bidi (Trojan-Source) stripping, leetspeak normalization.
- Recursive decoding of base64, hex, url-encoding, and rot13, with per-layer
  tagging so findings know where a payload was hidden.
- Multi-detector architecture: PatternDetector, RoleMarkerDetector,
  StructuralDetector, ObfuscationDetector.
- Multilingual rules (English, Spanish, French, German, Russian, Chinese).
- Egress firewall (`scan_action`) with secret detection and redaction.
- Canary tokens / secret tripwires (`mint_canary`, `register_canary`).
- Spotlighting / datamarking (`spotlight`) and trust-aware context assembly
  (`build_context`, `Trust`).
- MCP helpers: `cordon_tool` decorator and `guard_tool_result`.
- MCP server (`agent-cordon-mcp`, optional `[mcp]` extra) exposing scan / sanitize /
  egress tools to any MCP client, including Claude.
- Benchmark suite: labeled attack/benign corpus, `run_benchmark.py`, and a CI
  quality gate (100% recall, 0% false positives on the bundled corpus).
- Project hygiene: SECURITY.md, CODE_OF_CONDUCT.md, issue/PR templates,
  `py.typed` for shipped type hints, and ruff lint config.
- `Policy` configuration with presets (`strict`, `lenient`), allowlists,
  domain allow/deny, a pluggable second-stage verifier, and a telemetry hook.
- Severity x confidence scoring with a multi-vector bonus; `ScanResult.to_dict`
  and `.explain`.
- CLI: `scan`, `sanitize` (with `--spotlight`), and `scan-action`.

## [0.1.0]
- Initial heuristic scanner, `sanitize`, `wrap_as_data`, `guard`, and CLI.
