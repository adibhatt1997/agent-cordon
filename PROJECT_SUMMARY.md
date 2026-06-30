# cordon: project summary

A record of what we built, why, and exactly what is in the repository.

## What it is

`cordon` is an open source Python library that protects LLM agents from prompt
injection and data exfiltration. It scans the untrusted text an agent ingests
(web pages, tool results, emails, RAG chunks, MCP output) before the model reads
it, and it inspects the actions an agent is about to take before they run.

It has zero runtime dependencies, ships with tests and a benchmark, and can run
as an MCP server so it plugs into Claude and other agents.

## How we got here

1. Started from "build something useful with AI." Narrowed from broad business
   ideas to a concrete, buildable developer tool.
2. Chose the under served problem: most tools guard the system prompt, almost
   none guard the data flowing in from tools and MCP servers, which is where
   agents actually get hijacked.
3. The first name (agentward) turned out to be taken, so we renamed to `cordon`
   (a quarantine line) and sharpened the angle to the tool / MCP boundary.
4. Upgraded it from a basic regex checker into a real multi-layer engine, then
   added an egress firewall, canary tokens, an MCP server, a benchmark, and
   project hygiene files.

## What it does (capabilities)

- Detects instruction override, system-prompt extraction, role hijack,
  jailbreaks, secret and URL exfiltration, markdown image exfil, hidden HTML
  comments, fake authority, and silent-compliance pressure.
- Sees through obfuscation: unicode homoglyph folding, zero-width and bidi
  (Trojan-Source) stripping, leetspeak normalization, and recursive
  base64 / hex / url / rot13 decoding.
- Multilingual rules: English, Spanish, French, German, Russian, Chinese.
- Egress firewall (`scan_action`): blocks outbound tool calls that send secrets
  to disallowed domains, and can redact secrets.
- Canary tokens: register a secret or system-prompt signature; if untrusted
  content echoes it back, that is flagged as an extraction attempt.
- Spotlighting / datamarking and trust-tagged context assembly.
- Pluggable second-stage LLM verifier for gray-zone content, plus a telemetry
  hook for logging and alerts.
- A CLI (`cordon scan`, `sanitize`, `scan-action`) and an MCP server
  (`cordon-mcp`).

## Results

- 31 tests pass.
- Benchmark on the bundled 51-sample corpus: 100% detection (recall),
  0% false positives, 100% precision.
- Engine code about 1,400 lines; tests and benchmark about 370 lines.
- Single clean git commit, ready to push.

## Repository contents

### Source (`cordon/`)
- `__init__.py` — public API.
- `models.py` — Finding and ScanResult data types.
- `normalize.py` — variant building: normalization and recursive decoding.
- `rules.py` — the multilingual detection rule catalog.
- `detectors.py` — pattern, role-marker, structural, and obfuscation detectors.
- `canary.py` — canary token registry and tripwires.
- `scanner.py` — the engine: orchestration, scoring, optional verifier.
- `sanitize.py` — sanitize, spotlight, wrap_as_data, trust-aware context, guard.
- `egress.py` — the outbound action firewall and secret redaction.
- `mcp.py` — MCP / tool-boundary helpers.
- `server.py` — runs cordon as an MCP server.
- `cli.py` — command-line interface.
- `py.typed` — marks the package as typed.

### Tests (`tests/`)
- `test_cordon.py` — full feature coverage.
- `test_benchmark.py` — quality gate on detection rate and false positives.

### Benchmark (`benchmarks/`)
- `corpus.jsonl` — labeled attack and benign samples.
- `run_benchmark.py` — runs the corpus and reports metrics.

### Examples (`examples/`)
- `openai_tool_calling.py` — guard tool output in an OpenAI loop.
- `mcp_tool_guard.py` — guard MCP tools and outbound actions.

### Docs and project files
- `README.md` — main documentation and quickstart.
- `ARCHITECTURE.md` — design and extension points.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md` — community files.
- `CHANGELOG.md` — version history.
- `LICENSE` — MIT.
- `pyproject.toml` — packaging and console scripts.
- `.github/` — CI workflow and issue / PR templates.

## How to push it to GitHub

From inside the project folder, after creating an empty repo named `cordon`:

```bash
# easiest, with the GitHub CLI:
gh auth login
gh repo create cordon --public --source=. --remote=origin --push

# or standard git:
git remote add origin https://github.com/YOUR_USERNAME/cordon.git
git branch -M main
git push -u origin main
```

Before publishing: replace `YOUR_USERNAME` in `pyproject.toml`, `README.md`, and
`.github/ISSUE_TEMPLATE/config.yml`, and confirm the `cordon` name is free on
PyPI if you plan to release there.

## Honest limitations

`cordon` is a strong heuristic layer, not a complete defense. It can miss novel
attacks and can occasionally flag benign text. It is meant to be one part of
defense in depth, alongside least-privilege tools, confirmation on irreversible
actions, and keeping real secrets out of model context.
