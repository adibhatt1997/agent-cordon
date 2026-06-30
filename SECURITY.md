# Security Policy

`agent_cordon` is a defensive security tool, so we take its own correctness seriously.

## Supported versions

The latest released `0.x` line receives fixes. Pin a version in production and
review the [CHANGELOG](CHANGELOG.md) before upgrading.

## Reporting a vulnerability or a bypass

If you find a way to slip an injection past `agent_cordon`, or a defect in the egress
firewall, please report it.

- For a **detection bypass** (a payload agent_cordon should flag but does not),
  opening a public issue with a minimal reproduction is welcome and encouraged.
  A failing test is the ideal report and usually the fastest fix.
- For a **sensitive vulnerability** (for example, a way to make agent_cordon itself
  crash, hang, or be abused), please report privately via GitHub Security
  Advisories ("Report a vulnerability" on the Security tab) rather than a public
  issue.

Please include: agent_cordon version, a minimal input that reproduces the problem,
what you expected, and what happened.

## Scope and expectations

`agent_cordon` is one layer of defense in depth, not a guarantee. It is a heuristic
engine and will never catch every attack. Treat a clean result as "no known
signal", not "proven safe". Reports that simply note "heuristics can be evaded"
without a concrete payload are acknowledged but already covered by the README's
Limitations section.

## Disclosure

We aim to acknowledge reports within a few days and to ship a fix or mitigation
for confirmed issues as quickly as is practical, crediting the reporter unless
they prefer otherwise.
