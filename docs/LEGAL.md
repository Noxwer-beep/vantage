# Legal and ethical boundaries

Vantage exists to make authorized testing easier, not to make unauthorized testing
easy. This document is about the difference.

## The short version

Scanning a system you do not own, without permission, is a criminal offence in
most jurisdictions — even if nothing is exploited. A port scan touches thousands
of services you do not administer and generates traffic in someone else's logs.

You may run Vantage against:

- systems you own;
- systems you administer as part of your job, with your employer's approval;
- client systems under a signed engagement, inside the agreed scope and window;
- deliberately vulnerable training environments (HTB, THM, VulnHub, DVWA, your own
  lab) where the platform's rules allow scanning.

You may not run it against anything else. "It's just a scan" is not a defence.

## What the law says

| Jurisdiction | Provision |
|---|---|
| Germany | §202a StGB (Ausspähen von Daten), §202b (Abfangen), §202c (Vorbereiten) |
| EU | Directive 2013/40/EU on attacks against information systems |
| United States | Computer Fraud and Abuse Act, 18 U.S.C. §1030 |
| United Kingdom | Computer Misuse Act 1990, ss. 1–3 |
| Austria / Switzerland | §118a StGB / Art. 143 StGB |

Unauthorized port scanning has been prosecuted in Germany on the basis of §202a
when it probed services beyond what a public interface legitimately offers. Whether
a scan crosses the line depends on the target, the technique and the intent — which
is precisely why written authorisation is the only reliable protection.

## What Vantage enforces

The tool cannot verify that your permission is real. It can, and does, force you to
state it and record what you claimed:

1. **An explicit authorisation statement.** Without `--authorized` (or confirming in
   an interactive prompt, or ticking the box in the web UI) the scan does not start.
   Non-interactive runs without it exit with code 2.
2. **Scope enforcement.** If a scope file declares networks, every resolved target
   address must fall inside one of them. Otherwise: refusal, before any packet.
3. **Public address gating.** Public IPs are refused unless `--allow-public` is
   passed deliberately.
4. **Range ceilings.** A typo like `10.0.0.0/8` becomes a refusal, not an incident.
   Override only with `--allow-large`.
5. **Target hardening.** Multicast, broadcast and unspecified addresses are refused;
   shell metacharacters in a target are rejected outright.
6. **An audit trail.** Every decision — authorized *and* refused — is appended to
   `~/.local/share/vantage/logs/audit.jsonl` with timestamp, operator, hostname,
   target, scope fingerprint and statement.

Example audit line:

```json
{"ts": "2026-01-04T10:12:33", "event": "authorized", "operator": "nox",
 "host": "workstation", "target": "192.168.1.0/24",
 "scope": "homelab-q1", "scope_fingerprint": "548e6ee9b0fac462",
 "statement": "I HAVE PERMISSION"}
```

Every report carries the scope name, its network fingerprint, the operator and the
statement, so a report can be tied back to the authorisation that produced it.

## What Vantage deliberately does not do

These are ethical limits baked into the design, not missing features:

- **No authentication attempts.** No passwords, no hashes, no default-credential
  guessing. `mysql-empty-password` and similar are NSE *checks*, not brute force.
- **No exploitation.** Nothing launches an exploit, opens a shell, or writes data.
- **No evasion.** No decoys, fragmentation, spoofing or source-address hiding.
  Scans should be attributable to you.
- **No `unsafe=1`.** Several NSE scripts can crash services on fragile or embedded
  devices; Vantage never enables them.
- **No remote control.** The web UI binds to loopback and has no auth because it is
  not meant to be reachable from anywhere else.

## Working on a client engagement

A workable checklist:

1. **Written scope.** Networks, individual hosts, excluded systems, techniques
   allowed, time window, emergency contact. Both signatures.
2. **Turn it into a scope file.** `vantage scope new --name client --targets ...`
   Commit it next to the report.
3. **Use the narrowest profile that answers the question.** `quick` for asset
   inventory; `standard` for a report; `deep` only when the window allows it.
4. **Respect the window.** `--timing 2` during business hours.
5. **Keep the audit log.** It is evidence that you stayed inside the scope.
6. **Report honestly.** Confidence levels exist so you do not overstate. A report
   full of `possible` items, clearly labelled, is worth more than one full of
   unjustified certainties.
7. **Delete the data when the engagement ends**, unless the contract says otherwise.

## Responsible disclosure

If a scan finds something serious on a system you were authorized to test, report it
through the agreed channel within the agreed timeframe. Do not test the finding
further without permission — "I was already in scope" rarely covers exploitation.

If you find something serious on a system you were *not* authorized to test, stop
and use a disclosure channel: a `security.txt`, the vendor's security contact, or a
coordinating CERT. The German BSI and most national CERTs accept reports.

## The honest summary

The guardrails in this tool raise the cost of doing something careless. They do not
transfer responsibility. If you point Vantage at a network and you did not have
permission, that is on you, and the audit log will say exactly what you claimed.
