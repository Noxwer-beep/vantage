# Architecture

Vantage is a thin orchestrator around tools that already exist, plus three places
where it adds real value: the authorisation gate, the finding model, and reporting.

```
                     ┌───────────────────────┐
   CLI (rich)  ──────┤                       │
                     │        Engine         ├───► ScanResult ──► Report (html/md/json)
   Web (flask) ──────┤   (phase orchestration)│                └──► Store (sqlite)
                     └───────────┬───────────┘
                                 │
        ┌────────────┬───────────┼───────────┬─────────────┐
        ▼            ▼           ▼           ▼             ▼
   NmapRunner    webcheck     tlscheck    analyzer      coverage
  (discovery,   (whatweb,    (openssl    (NSE grading,  (what was
   ports, svc,    nikto)       s_client)   exposure KB,   NOT done)
   vuln)                                   EOL table,
                                           web rules)
                                 │
                                 ▼
                          scope.authorize()
                     ┌──────────────────────┐
                     │ Guard = proof that a │
                     │ target was checked   │
                     └──────────────────────┘
```

## Module map

| File | Responsibility |
|---|---|
| `vantage/scope.py` | The legal boundary. Target validation, scope files, the authorisation gate, audit log. |
| `vantage/nmap.py` | Builds nmap command lines, streams stderr for progress, parses `-oX -` XML. |
| `vantage/webcheck.py` | whatweb JSON parsing; nikto run + output normalisation. |
| `vantage/tlscheck.py` | `openssl s_client` handshakes: cert details, trust, expiry, legacy protocols. |
| `vantage/analyzer.py` | Turns observations into findings. Owns every severity/confidence decision. |
| `vantage/models.py` | `Host`, `Port`, `Finding`, risk scoring. |
| `vantage/engine.py` | Phase order, progress events, graceful degradation, `ScanResult`. |
| `vantage/store.py` | SQLite schema, scan/finding persistence, history queries. |
| `vantage/report.py` | Jinja2 rendering to HTML/Markdown/JSON. |
| `vantage/cli.py` | argparse + rich presentation. |
| `vantage/web/app.py` | Flask routes, thread-per-scan job registry, JSON polling API. |
| `vantage/knowledge/ports.json` | Exposure table: risky service → severity, explanation, remediation. |
| `vantage/knowledge/eol.json` | Curated end-of-life version thresholds. |

## The five decisions that matter

### 1. The Guard is the only way in

`Engine` takes a `Guard`, and a `Guard` can only be produced by
`scope.authorize()`. There is no code path that scans without one. The gate:

1. refuses without an explicit statement;
2. validates the target token (rejects shell metacharacters, malformed CIDR);
3. resolves hostnames, then checks *every* returned address (no DNS smuggling);
4. refuses out-of-scope addresses before any tool runs;
5. refuses public addresses unless `--allow-public`;
6. refuses ranges above a host ceiling unless `--allow-large`;
7. writes an audit line either way.

A refusal is a normal outcome with its own exit code (2), not an exception that
gets swallowed.

### 2. Observations and interpretations are different objects

`Host`/`Port` hold what came back from the wire. `Finding` holds an
interpretation, and carries `severity`, `confidence`, `evidence`, `detail`,
`remediation` and `source`. Nothing in the report is a bare claim: each finding can
be traced to the tool output that produced it.

### 3. Confidence is a first-class field

`confirmed / likely / possible / informational`. This is what stops the tool from
lying. A version banner is `possible`; an NSE "State: VULNERABLE" is `confirmed`;
a nikto hit is `possible` with a note that nikto produces false positives. The
report renders both axes side by side.

### 4. Phases degrade, they do not crash

Every phase is wrapped: a timeout in the vuln phase yields a scan that still
reports ports and services, plus an explicit warning that the vuln results are
incomplete. Silent completeness is worse than visible incompleteness, so
`coverage_notes()` always prints what was *not* done.

### 5. The report is data, not a template render of live state

`ScanResult.to_dict()` is the single serialised form. It goes to SQLite, to JSON,
to the HTML/Markdown renderers, and to the web UI's API. Re-rendering an old scan
months later uses the same path as the fresh one.

## Progress reporting

`Engine` emits events through a callback:

```
phase           {key, label, index, total}
phase_done      {key, status, note, progress}
log             {message}
warning         {message}
progress        {message, progress}
finding         {finding dict}
done            {full result dict}
```

The CLI renders these with rich. The web app writes them into a per-scan state
dict guarded by a lock, and the page polls `/api/scan/<id>`. No websockets, no
build step, no frontend framework.

## Threading model (web)

One `threading.Thread` per scan, daemonised. `JOBS` is a dict of scan-id → state,
guarded by a single `LOCK`. The registry is capped at 40 entries; completed scans
are evicted first. Results are persisted to SQLite when the thread finishes, so a
restarted process can still serve old scans from the database.

## Why shell out instead of using a library

- `python-nmap` adds a dependency and still just parses XML.
- nmap's XML schema is stable and documented; parsing it is ~80 lines.
- Shelling out keeps the exact command line visible in the logs — which matters
  when someone asks "what did this tool actually run against my host?".
- It also means Vantage inherits the system's nmap scripts and updates for free.

## Deliberate non-goals

- **No exploitation.** No Metasploit, no SQLi/command-injection exploitation.
- **No credential attacks.** No brute force, no password spraying.
- **No evasion.** No fragmentation, decoys, or spoofing. Scans are meant to be
  visible and attributable.
- **No agent/multi-host distribution.** One process, one target set.
- **No UDP by default.** It is slow and noisy; the profile flag exists but is off.

These are choices about what the tool is for: producing a defensible report for an
engagement you are already authorised to run.
