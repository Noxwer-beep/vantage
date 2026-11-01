# Strategies

A profile that only says "how deep" is a dial, not a decision. Vantage's
strategies encode the *question* you are asking, because most real scans are one
of a handful of intents — and each intent wants a different set of tools pointed
at it.

Every strategy is a named phase list. Nothing else. That means a strategy can
never describe a phase it will not run, and `--only` / `--no-*` edit the same
list rather than toggling independent booleans that could drift out of sync.

## The list

### `discover` — which addresses are alive?

**Phases:** host discovery only. **Nothing else.**

No port scanning, no probes, no findings. Use it before a real scan to shrink a
/24 to the nine things that actually exist, or to check whether a range is
routed to you at all. It is also the cheapest way to confirm scope ("is
10.0.10.40 even mine?") before committing to a deeper run.

It *always* runs discovery, even for a single host — that is the point of the
strategy.

### `quick` — a first look

**Phases:** top 100 ports, version banners.

Seconds per host. Enough to know whether a box is a Windows file server, a Linux
web host, or nothing interesting. Version detection is on because a banner costs
one extra connection and tells you far more than a port number.

### `gentle` — fragile gear

**Phases:** top 100 ports, versions, `-T2`, one host at a time.

Same coverage as `quick`, different manners. Timing 2 and `--max-hostgroup 1`
stop a sweep from piling parallel probes onto a decade-old switch, a printer, or
an IPMI controller that will fall over. If you have ever crashed a device with
nmap, this is the strategy you wanted.

It is slow by design: about a minute per host.

### `inventory` — what runs where

**Phases:** top 1000 ports, versions.

The asset-list strategy. No NSE, no web crawling, no TLS — nothing intrusive, so
it is safe to run against production during business hours. You get hosts, open
ports, service names and versions: enough to build an inventory or to see what
walked in since last month.

### `hardening` — crypto and patch posture

**Phases:** top 1000 ports, versions, TLS inspection.

Answers "are my certificates and protocols in order?" without touching the web
application layer. Expired certs, self-signed certs, unverifiable chains, TLS 1.0
and 1.1 still accepted, end-of-life banners.

Use it as a pre-audit check, or monthly against anything terminating TLS.

### `web` — the HTTP surface

**Phases:** top 1000 ports, versions, whatweb + nikto, TLS.

What the server is, what it leaks, which security headers are missing, whether
directory listing is on, whether backups or `.git` are exposed — plus certificates.
The most common real-world request: "is my site exposing itself?"

nikto output is always tagged `possible`, because it is a heuristic scanner.

### `vuln` — known issues, no web noise

**Phases:** top 1000 ports, versions, NSE `vuln`.

For hosts you already understand: you know it is a file server, you want to know
whether it is a *vulnerable* file server. Skips nikto, which keeps the runtime
down and the output focused on NSE verdicts.

### `standard` — the assessment

**Phases:** top 1000 ports, versions, NSE vuln, web review, TLS.

Everything except full port coverage. The default, because most engagements want
the whole picture and top-1000 covers the overwhelming majority of real services.

### `deep` — full coverage

**Phases:** all 65535 ports, versions at intensity 7, NSE vuln, web, TLS.

For the box you suspect is hiding something on port 31337. Ten to sixty minutes
per host. Note that this changes *port coverage*, not intrudence — the same
non-exploiting checks run, just against more ports.

## Composing your own

The list is a starting point, not a cage:

```bash
# inventory + web review + TLS, skipping NSE
vantage scan 10.0.0.5 -p inventory --only web,tls --authorized

# the full pipeline but no web crawling
vantage scan 10.0.0.5 -p standard --no-web --authorized

# deep, but only against a specific port set
vantage scan 10.0.0.5 -p deep --ports 22,80,443,8080 --authorized
```

`--only` and `--no-*` are applied to the phase list, so the plan is always a
subset of the canonical order (`discover → ports → services → vuln → web → tls`)
and always ends with analysis.

Dependent phases need ports: dropping `ports` removes `services`, `vuln`, `web`
and `tls` automatically, because none of them can run without a port list.

## Discovery policy

`discover` runs as its own phase, but port-scanning strategies also ping-sweep
first when the target is a range:

| Policy | Behaviour |
|---|---|
| `auto` (default) | discovery runs for ranges, skipped for a single host |
| `always` | always, even for one host |
| `never` | never — scan everything with `-Pn` |

`auto` exists because a single-host scan does not need a ping sweep (the port
scan answers the question anyway), while a /24 absolutely does: without it you
spend the whole port scan on addresses that do not exist.

## Why not just `--profile`?

`--profile` still works and means the same thing. "Strategy" is the honest name
for what these are — and it leaves room for the next one without renaming a flag
people already have in scripts.
