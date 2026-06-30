# Changelog

All notable changes to cordon are documented here. Format roughly follows
Keep a Changelog; this project uses semantic versioning.

## [0.2.0]

The advanced engine. Renamed from the original prototype to `cordon`.

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
- MCP server (`cordon-mcp`, optional `[mcp]` extra) exposing scan / sanitize /
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
