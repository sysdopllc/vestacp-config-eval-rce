# VestaCP config-parser `eval` sinks → root RCE (VESTACP-2026-001)

Security advisory for the **original Vesta Control Panel (VestaCP) ≤ 0.9.8-26**
(`github.com/serghey-rodin/vesta`, vestacp.com — unmaintained since September
2019): the shared config parser in `func/main.sh` evaluates user-controllable
`KEY='value'` lines with `eval` inside `v-*` scripts that run as root — an
authenticated panel user can escalate to full root on the hosting node.

- **GHSA:** [GHSA-m2mc-xwq7-pw72](https://github.com/sysdopllc/vestacp-config-eval-rce/security/advisories/GHSA-m2mc-xwq7-pw72)
- **Severity:** Critical, CVSS 9.9 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`)
- **Class:** CWE-78 / CWE-95

This is the same sink class fixed in the maintained fork **HestiaCP** in July
2026 — [CVE-2026-84981](https://github.com/hestiacp/hestiacp/security/advisories/GHSA-w3mx-xq85-8qqc),
[CVE-2026-84984](https://github.com/hestiacp/hestiacp/security/advisories/GHSA-cr7q-frhq-xw4v),
[CVE-2026-84979](https://github.com/hestiacp/hestiacp/security/advisories/GHSA-5fpv-c8rg-x6r3) —
never disclosed or fixed for the original VestaCP, its ancestor. It is also
distinct from VestaCP's earlier CVEs (CVE-2019-9859 PHP layer,
CVE-2021-30462/30463 LPE chain, CVE-2022-3967 `sed` injection); see the
advisory's *Prior art* section. Published for the install base still running
VestaCP in production (widely shipped in VPS templates).

## Contents

- [`advisory/VESTACP-2026-001.md`](advisory/VESTACP-2026-001.md) — full
  advisory: affected sinks, exploitation path, impact, prior art, scope,
  mitigation, timeline.
- [`poc/poc-eval-sink.sh`](poc/poc-eval-sink.sh) — self-contained proof of
  concept: simulates the vulnerable `eval` parse on a crafted conf line and
  shows the hardened parser neutralizing it. Runs in a `mktemp` sandbox; does
  not require a VestaCP install.
- [`mitigation/non-eval-parser.sh`](mitigation/non-eval-parser.sh) — drop-in
  `parse_object_kv_list` + porting recipe for every `eval` site.

## Running the PoC

```bash
bash poc/poc-eval-sink.sh
```

Expected: the vulnerable parse creates a marker file (injection executed); the
hardened parse leaves it inert (value kept literal).

## Reporter

**Bryan Ramirez — SYSDOP LLC** · security@sysdop.com

Discovered during a defensive security audit of production hosting
infrastructure, August 2026. Disclosed October 2026.
