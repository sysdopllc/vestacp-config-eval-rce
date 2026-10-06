# VestaCP config-parser `eval` sinks → root RCE (VESTACP-2026-001)

Security advisory for **Vesta Control Panel ≤ 0.9.8-26** (unmaintained since
September 2019): the shared config parser in `func/main.sh` evaluates
user-controllable `KEY='value'` lines with `eval` inside `v-*` scripts that run
as root — an authenticated panel user can escalate to full root on the hosting
node.

This is the same sink class fixed in the downstream fork **HestiaCP**
([GHSA-w3mx-xq85-8qqc](https://github.com/hestiacp/hestiacp/security/advisories/GHSA-w3mx-xq85-8qqc),
[GHSA-cr7q-frhq-xw4v](https://github.com/hestiacp/hestiacp/security/advisories/GHSA-cr7q-frhq-xw4v),
[GHSA-5fpv-c8rg-x6r3](https://github.com/hestiacp/hestiacp/security/advisories/GHSA-5fpv-c8rg-x6r3)),
never disclosed or fixed for VestaCP itself. Published for the install base
still running it in production (widely shipped in VPS templates).

## Contents

- [`advisory/VESTACP-2026-001.md`](advisory/VESTACP-2026-001.md) — full
  advisory: affected sinks, exploitation path, impact, mitigation, timeline.
- [`poc/poc-eval-sink.sh`](poc/poc-eval-sink.sh) — self-contained proof of
  concept: simulates the vulnerable `eval` parse on a crafted conf line and
  shows the hardened parser neutralizing it.
- [`mitigation/non-eval-parser.sh`](mitigation/non-eval-parser.sh) — drop-in
  `parse_object_kv_list` + porting recipe for every `eval` site.

## Reporter

**Bryan Ramirez — SYSDOP LLC** · bryan@sysdop.com

Discovered during a defensive security audit of production hosting
infrastructure, August 2026. Disclosed October 2026.
