# Findings: severity, confidence, and the rules

Every finding in a Vantage report answers four questions:

1. **What is it?** — `title`, `category`
2. **Where is it?** — `host`, `port`, `protocol`, `service`
3. **How do we know?** — `evidence` (raw tool output), `source`, `confidence`
4. **What should be done?** — `remediation`, `references`

## Severity

How bad it would be if the finding is real.

| Level | Meaning | Examples |
|---|---|---|
| `critical` | Remote compromise, or an unauthenticated control plane | MS17-010 confirmed, Heartbleed, unauthenticated Docker API |
| `high` | Serious exposure or a confirmed exploitable condition | Telnet reachable, expired cert, TLS 1.0 accepted, exposed VNC |
| `medium` | Weakens defence in depth, or a plausible issue | SMB reachable, self-signed cert, missing HSTS |
| `low` | Hardening gap, minimal standalone impact | Directory listing, missing X-Frame-Options, unencrypted HTTP |
| `info` | Context, not a weakness | Server banner, technology fingerprint |

## Confidence

How sure *this scan* is that the finding is real. This is the field that keeps the
tool honest.

| Level | Meaning | Produced by |
|---|---|---|
| `confirmed` | A check returned a positive result | NSE `State: VULNERABLE`, a completed TLS 1.0 handshake, an open port, an expired cert read from the wire |
| `likely` | Strong signal, one manual step from confirmed | NSE `State: LIKELY VULNERABLE`, cert/hostname mismatch heuristics |
| `possible` | Heuristic hit needing manual review | **all** nikto output, end-of-life version comparison, un-graded NSE text |
| `informational` | Observation only | `info` severity items |

### The rules, precisely

**NSE scripts** (`vantage/analyzer.py`)

- Output contains `State: NOT VULNERABLE` → **no finding**. A negative is a result.
- Output contains `State: VULNERABLE` or the word "vulnerable" (without "not") →
  `confirmed`.
- `State: LIKELY VULNERABLE` → `likely`.
- Output starting with `ERROR`, `Couldn't`, `failed`, `unknown`, `No response` →
  **no finding** — a script that failed to run has not told us anything.
- Severity comes from a curated table (`NSE_META`, ~60 script ids). An unlisted
  script that announces vulnerability is graded `high`; an unlisted script that
  does not is dropped.
- CVE ids are regex-extracted from the output and turned into NVD links.
- `ssl-cert`, `ssl-date`, `ssl-enum-ciphers` are skipped when the TLS phase already
  inspected that endpoint, so the same fact is not reported twice.

**Exposure** (`knowledge/ports.json`)

- Keyed by nmap service name, falling back to port number.
- Always `confirmed` — the port *is* open. The `detail` says explicitly that this
  records reachability only and that no exploit was attempted.
- An `http` service on 443/8443/9443 is not reported as "unencrypted HTTP".

**Versions** (`knowledge/eol.json`)

- Only a curated list of products, with an explicit `max_safe` version.
- Always `possible`, and the `detail` says why: banners lie, distributors backport
  fixes without changing the version number.
- No version parsed → no finding. Never guess a version from a product name.

**Web** (nikto / whatweb)

- All nikto output is `possible`, with the note that nikto is pattern-based.
- Severity by keyword class: default credentials and injection → `high`; exposed
  `.git`/backup/config → `medium`; missing headers, directory listing → `low`.
- Missing-header findings carry the exact header line to add.
- whatweb fingerprints are `info`, `confirmed` — they are facts, not weaknesses.

**TLS** (`vantage/tlscheck.py`)

- Expired certificate → `high`, `confirmed`.
- Expires within 30 days → `medium`, `confirmed`.
- Self-signed → `medium`, `confirmed`.
- Chain does not verify → `medium`, `confirmed`.
- Hostname mismatch → `medium`, `likely` (SAN parsing is heuristic).
- TLS 1.0 or 1.1 handshake completed → `high`, `confirmed`, referencing RFC 8996.

## The risk score

A 0-100 triage number, not a CVSS score. Two components:

```
weighted  = Σ SEVERITY_WEIGHT[severity] × CONFIDENCE_SCALE[confidence]
volume    = 100 × (1 − e^(−weighted / 60))
floor     = max over findings of SEVERITY_FLOOR[severity] × confidence_scale
score     = min(100, round(max(volume, floor)))
```

The floor exists because volume alone is misleading: twenty low findings would
otherwise outrank one confirmed critical. With the floor, a single confirmed
critical scores ≥82 by itself.

| Score | Grade |
|---|---|
| 80-100 | critical |
| 55-79 | high |
| 30-54 | medium |
| 10-29 | low |
| 0-9 | clean |

## Deduplication

Identity is `sha1(host | port | category | lowercased title)`. When two findings
collide, the more severe / more confident one wins, and the richer evidence is
kept. This is what collapses "nmap found it during the vuln phase and again during
the service phase" into one line.

## What a clean report means

It means nothing was detected — not that the target is secure. Every report says
this in as many words, and lists the coverage gaps that explain why:

- TCP only (no UDP)
- no authentication attempted
- no exploit executed
- which phases were skipped or failed

A report that fails to say what it did not look at is a report that is wrong by
omission.
