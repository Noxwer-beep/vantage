# Development

## Layout

```
vantage/
├── vantage/                  the package
│   ├── config.py             profiles, severity model, paths, limits
│   ├── scope.py              authorisation gate + scope files + audit log
│   ├── models.py             Host, Port, Finding, risk scoring
│   ├── nmap.py               nmap invocation, XML parsing
│   ├── webcheck.py           whatweb + nikto
│   ├── tlscheck.py           openssl s_client probes
│   ├── analyzer.py           observations → findings
│   ├── engine.py             phase orchestration, events
│   ├── store.py              SQLite
│   ├── report.py             HTML/MD/JSON rendering
│   ├── cli.py                argparse + rich
│   ├── templates/            report templates (Jinja2)
│   ├── knowledge/            ports.json, eol.json
│   └── web/                  Flask app, templates, static
├── tests/                    stdlib unittest, 129 tests
├── docs/
├── vantage.py                checkout launcher (no install needed)
└── pyproject.toml
```

## Running

```bash
./vantage.py doctor
./vantage.py scan 127.0.0.1 --authorized --profile quick
python3 -m vantage scan 127.0.0.1 --authorized      # equivalent
```

## Tests

```bash
python3 -m unittest discover -s tests -t .
python3 -m unittest tests.test_scope -v             # one module
```

No network, no nmap, no extra packages. Everything that would touch the wire is
replaced by a fixture: nmap XML is a captured string, scope checks use loopback
literals, storage uses a temporary `VANTAGE_DATA_DIR`.

What the suite covers:

| Module | Focus |
|---|---|
| `test_scope.py` | Target validation, scope membership, refusals, audit lines, scope-file parsing |
| `test_analyzer.py` | NSE grading (confirmed/likely/negative/error), exposure KB, EOL table, nikto rules, dedupe, scoring |
| `test_nmap_parse.py` | XML parsing, closed/down handling, IPv6, command construction |
| `test_report.py` | Rendering in all three formats, HTML escaping, storage round-trip |

Tests set `VANTAGE_DATA_DIR` before importing `vantage.config`, because paths are
resolved at call time.

## Adding a finding rule

1. **Service exposure** → add an entry to `vantage/knowledge/ports.json` under
   `services`, keyed by the nmap service name. Add a `port_fallback` entry if nmap
   will not identify the service.
2. **End-of-life version** → add a rule to `vantage/knowledge/eol.json` with
   `match` (lowercase substring of the product), `max_safe` as `[major, minor, patch]`,
   severity, explanation and remediation. Keep it defensible from a banner alone.
3. **NSE script** → add to `NSE_META` in `analyzer.py` as
   `(severity, title, category)`. Unlisted scripts still get graded from their
   output text, so this is only needed to improve precision.
4. **Web pattern** → add a `(regex, severity, title, category)` tuple to `NIKTO_RULES`.
   Order matters: the first match wins.

Whatever you add, keep the honesty rule: if the evidence cannot prove it, the
confidence is `possible`, and the `detail` says why.

## Adding a scan phase

1. Write the checker as a module returning plain dataclasses.
2. Add a flag to `Profile` in `config.py` and a `PHASE_LABELS` entry in `engine.py`.
3. Insert the phase into `Engine.plan()` and run it in `Engine.run()`, wrapped like
   its neighbours (`_start_phase` / `_end_phase` / `_fail_phase`).
4. Emit findings via `analyzer` — do not append to `result.findings` directly, or
   dedupe and sorting will miss them.
5. Add a coverage note so the report says whether it ran.

## Extending the web UI

Templates live in `vantage/web/templates`, one stylesheet in
`static/app.css`. The scan page polls `/api/scan/<id>`; add fields to the job state
dict in `_make_emit` / `_run_job` and they appear in the JSON automatically.

There is deliberately no JS build step and no framework. If a change needs more
than a `<script>` block, reconsider the change.

## Style

- Standard library first. `rich` and `flask` are the only runtime dependencies,
  and both are optional (CLI works without flask, web needs both).
- Dataclasses for data, plain functions for logic, classes only where state lives.
- Every refusal path gets a specific message and an exit code.
- No bare `except:`. Where a phase must not kill the scan, catch `Exception`, log
  the type and message, and record it in `result.errors`.
- Comments explain *why*, not *what*.

## Known limits

- Unprivileged runs use a TCP connect scan (`-sT`); no OS detection.
- UDP is defined in the profile model but not implemented.
- nikto and whatweb are optional; their absence degrades the report, and the
  coverage notes say so.
- The web UI holds jobs in memory; a restart loses in-flight scans (completed ones
  are in SQLite).
- IPv6 is parsed and scope-checked, but nmap flags are IPv4-tuned.
