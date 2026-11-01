# Usage

## Commands

```
vantage scan <target>     scan a host or network
vantage strategies        list strategies and when to use them
vantage diff <a> <b>      compare two stored scans
vantage ui                local web console
vantage history           list stored scans
vantage show <scan-id>    detail for one scan
vantage findings          query findings across scans
vantage report <scan-id>  re-render HTML/Markdown/JSON
vantage scope check|new   work with scope files
vantage doctor            check the toolchain
vantage audit             show the authorisation log
```

## `vantage scan`

```
vantage scan TARGET [options]
```

`TARGET` is an IP, a CIDR range, or a hostname. Shell metacharacters are rejected
outright, so a mangled argument fails instead of becoming an injection.

### Required-to-know flags

| Flag | Effect |
|---|---|
| `--authorized` | The authorisation statement. Absent and non-interactive → exit 2. |
| `-s, --scope FILE` | Enforce a scope file. Out-of-scope targets are refused before scanning. |
| `-p, --profile NAME` | Scan strategy: `discover`, `quick`, `gentle`, `inventory`, `hardening`, `web`, `vuln`, `standard` (default), `deep`. `--strategy` is an alias. |
| `--allow-public` | Permit public addresses. Do not use without written permission. |
| `--allow-large` | Permit ranges above the host ceiling (default 4096 addresses). |
| `--max-hosts N` | Change that ceiling. |

### Tuning

| Flag | Effect |
|---|---|
| `--ports SPEC` | Override nmap's port spec, e.g. `22,80,443` or `-p-`. |
| `--timing N` | nmap `-T` value. 1–2 for fragile devices, 3 default, 4–5 loud. |
| `--no-vuln` | Skip NSE vuln scripts (much faster). |
| `--no-web` | Skip nikto/whatweb. |
| `--no-tls` | Skip TLS inspection. |
| `--no-services` | Skip version detection. |
| `--only PHASES` | Force phases on, comma separated: `--only web,tls`. |
| `--plain` | Line-by-line output instead of the live dashboard. |
| `--max-hostgroup N` | Hosts scanned in parallel (default 8). Lower is gentler. |

### Output

| Flag | Effect |
|---|---|
| `-o, --output DIR` | Where to write reports (default `~/.local/share/vantage/reports`). |
| `--show N` | Findings printed to the terminal (default 20). |
| `--json` | Print the whole result as JSON instead of a table. |
| `--open-report` | Open the HTML report when done. |
| `--no-save` | Do not write to the database or disk. |
| `--dry-run` | Print the phase plan and exit without sending a packet. |
| `--fail-on LEVEL` | Exit 4 if a finding at `LEVEL` or worse exists. CI gate. |
| `-q / -v` | Quiet / stream tool output. |

### Exit codes

`0` ok · `1` error · `2` refused · `3` tool missing · `4` fail-on threshold met.

## Workflows

### First run on your own machine

```bash
vantage doctor
vantage scan 127.0.0.1 --profile quick --authorized
```

### A lab range, with a scope file

```bash
vantage scope new --name lab --targets 10.10.10.0/24 -o lab.json
vantage scan 10.10.10.0/24 --scope lab.json --authorized --profile standard
```

### A single host, deep, and open the report

```bash
vantage scan 10.10.10.50 --profile deep --authorized --open-report
```

### Fast sweep before a maintenance window

```bash
vantage scan 192.168.1.0/24 --profile quick --timing 2 --authorized
```

`--timing 2` is noticeably gentler on embedded devices and old switches.

### In CI (regression check on an internal service)

```bash
vantage scan stage.internal --scope ci.json --authorized \
        --no-web --no-tls --fail-on high --json > scan.json
echo "exit: $?"
```

### Comparing two scans

```bash
vantage history
vantage findings --host 10.10.10.50 --limit 50
vantage report <older-id> --format json > a.json
vantage report <newer-id> --format json > b.json
```

Findings carry a stable `key` (hash of host, port, category and title), so a
diff on that field is meaningful across runs.

## The web console

```bash
vantage ui                      # 127.0.0.1:8765
vantage ui --port 9000 --open
vantage ui --host 0.0.0.0       # only behind a firewall you trust
```

| Route | Purpose |
|---|---|
| `/` | New scan form + recent scans |
| `/scan/<id>` | Live progress, phase timeline, asset stream, findings |
| `/scan/<id>/report` | The full HTML report |
| `/scan/<id>/download/html\|md\|json` | Download |
| `/diff/<base>/<compare>` | What changed between two scans |
| `/history` | Everything stored |
| `/api/scan/<id>` | JSON status (what the page polls) |
| `/api/diff/<a>/<b>` | Machine-readable diff |
| `/help` | The reference page |

The console binds to loopback by default and has no authentication. It is not a
multi-user service — do not expose it.

## Reading terminal output

```
▸    Service & version detection                                    running…
✓    Port scan                              37 port(s) on 9 host(s)  28.4s
```

The scan draws a dashboard in place: a progress bar, the phase timeline with
per-phase durations, live host and port counters, the last three findings, and the
most recent tool message. It is disabled automatically when stdout is not a
terminal, under `--json`, and under `--plain`.

`✓` phase done · `–` skipped · `✗` failed · `▸` running · `·` pending. A failed
phase appears again under `errors`, and its consequence is spelled out in
`warnings`, because a phase that did not run is a coverage gap you need to know
about.

```
SEV          CONF        LOCATION                 FINDING                SOURCE
MEDIUM       confirme    127.0.0.1:5432/tcp       PostgreSQL reachable   exposure-kb
```

The `CONF` column is truncated here for width; the report has the full word.

## Diffing two scans

```
vantage diff 20261101-122514-3572 20261101-130513-6a37
```

```
  risk  30 → 28  ▼ -2   0 new · 17 resolved · 2 still present

RESOLVED  17
SEV          LOCATION                CONF         FINDING
MEDIUM       127.0.0.1:8080/tcp      possible     Outdated component: SimpleHTTP/0.6
...

CLOSED PORTS
  127.0.0.1:80, 127.0.0.1:8088, 127.0.0.1:8089, 127.0.0.1:8443
```

Sections: `NEW`, `RESOLVED`, `CHANGED` (severity or confidence moved), and port
changes. `--fail-on high` exits 4 when a *new* finding reaches that severity,
which is the piece you need to run this from cron and be told when something
regressed. `--markdown FILE` writes a shareable version.

Identity is the finding key — host, port, category and title — so a re-run of the
same scan against the same target lines up entry for entry.

## Troubleshooting

**"nmap is not installed"** → `vantage doctor`; `sudo apt install nmap`.

**Long scans** → the `vuln` phase with `--script vuln` is the slow one. Use
`--no-vuln` for a fast sweep, or `--ports` to narrow the surface.

**"refused: ... is a public address"** → by design. If you do have
authorisation, pass `--allow-public`, and keep the written approval.

**"refused: ... is outside scope ..."** → the target does not fall inside the scope
file. Fix the scope file or the target; do not widen the scope to make it pass.

**Scan reports nothing on a host that is up** → the host is filtering. Try
`--timing 2`, or `-Pn` behaviour is already applied for the port phase.

**nikto finds nothing** → it needs a reachable HTTP service and can be slow; it is
skipped automatically when absent.
