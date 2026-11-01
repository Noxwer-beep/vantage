"""Web surface checks: fingerprinting with whatweb, config review with nikto.

Both tools are optional. When absent, the phase is skipped with a note in the
run log rather than failing the scan.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable

from .config import Limits

LogFn = Callable[[str], None]


@dataclass
class WebTarget:
    url: str
    host: str
    port: int
    scheme: str = "http"


@dataclass
class WebResult:
    target: WebTarget
    plugins: dict[str, list[str]] = field(default_factory=dict)
    server: str = ""
    title: str = ""
    tech: list[str] = field(default_factory=list)
    raw: str = ""
    error: str = ""


@dataclass
class NiktoItem:
    target: WebTarget
    message: str
    method: str = "GET"
    uri: str = ""
    refs: list[str] = field(default_factory=list)

    @property
    def cves(self) -> list[str]:
        return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", self.message + " " + " ".join(self.refs))))


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def build_targets(hosts, ports=None) -> list[WebTarget]:
    """Derive web URLs from discovered hosts and open ports."""
    from .config import WEB_PORTS

    out: list[WebTarget] = []
    for host in hosts:
        for port in host.open_ports:
            if port.protocol != "tcp":
                continue
            name = (port.service or "").lower()
            is_web = (
                port.number in WEB_PORTS
                or "http" in name
                or name in {"ssl/http", "https", "http-proxy", "http-alt"}
                or (port.product and "http" in port.product.lower())
            )
            if not is_web:
                continue
            scheme = "https" if (port.number in (443, 8443, 9443, 10443) or "ssl" in name or "https" in name) else "http"
            hostname = host.hostname or host.address
            default_port = (scheme == "http" and port.number == 80) or (scheme == "https" and port.number == 443)
            netloc = hostname if default_port else f"{hostname}:{port.number}"
            out.append(WebTarget(url=f"{scheme}://{netloc}/", host=host.address, port=port.number, scheme=scheme))
    # de-duplicate on URL
    seen: set[str] = set()
    unique: list[WebTarget] = []
    for t in out:
        if t.url not in seen:
            seen.add(t.url)
            unique.append(t)
    return unique[:64]


def whatweb(target: WebTarget, log: LogFn | None = None, timeout: int = 60) -> WebResult:
    log = log or (lambda _m: None)
    res = WebResult(target=target)
    if not have("whatweb"):
        res.error = "whatweb not installed"
        return res
    cmd = [
        "whatweb",
        "--no-errors",
        "--quiet",
        "--log-json=-",
        "--user-agent",
        "Vantage/1.0 (authorized assessment)",
        target.url,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        res.error = "whatweb timed out"
        return res
    except OSError as exc:
        res.error = f"whatweb failed: {exc}"
        return res
    res.raw = proc.stdout.strip()
    if not res.raw:
        res.error = proc.stderr.strip()[:200] or "whatweb returned nothing"
        return res
    try:
        data = json.loads(res.raw)
    except json.JSONDecodeError:
        res.error = "whatweb output was not JSON"
        return res
    if isinstance(data, dict):
        data = [data]
    if not data:
        return res
    entry = data[0]
    plugins = entry.get("plugins", {}) or {}
    if isinstance(plugins, list):  # older whatweb versions emit a list
        merged: dict[str, list[str]] = {}
        for item in plugins:
            if isinstance(item, dict):
                for k, v in item.items():
                    merged.setdefault(k, []).extend(v if isinstance(v, list) else [str(v)])
        plugins = merged
    res.plugins = {k: (v if isinstance(v, list) else [str(v)]) for k, v in plugins.items()}
    for key in ("HTTPServer", "server"):
        if key in res.plugins:
            res.server = ", ".join(str(x) for x in res.plugins[key])
    if "Title" in res.plugins:
        res.title = ", ".join(str(x) for x in res.plugins["Title"])
    res.tech = sorted(k for k in res.plugins)
    log(f"whatweb: {target.url} → {', '.join(res.tech[:6]) or 'no fingerprint'}")
    return res


_NIKTO_INTERESTING = re.compile(r"^\+ ")
#: Closing statistics line ("7948 requests: 0 error(s) and 2 item(s) reported"), not a finding.
_NIKTO_SUMMARY = re.compile(r"^[\d,]+\s+requests?\s*:", re.IGNORECASE)


def nikto(target: WebTarget, log: LogFn | None = None, max_time: int = 240) -> list[NiktoItem]:
    """Run nikto and return its config findings.

    Nikto is heuristic: everything it reports is tagged 'possible' confidence
    downstream. Its job here is to surface configuration problems a port scan
    cannot see.
    """
    log = log or (lambda _m: None)
    if not have("nikto"):
        log("nikto not installed — skipping web config review")
        return []
    cmd = [
        "nikto",
        "-h",
        target.url,
        "-nointeractive",
        "-ask",
        "no",
        "-maxtime",
        f"{max_time}s",
        "-timeout",
        "8",
        "-useragent",
        "Vantage/1.0 (authorized assessment)",
    ]
    log(f"nikto: {target.url} (max {max_time}s)")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max_time + 90)
    except subprocess.TimeoutExpired:
        log(f"nikto: {target.url} exceeded its budget")
        return []
    except OSError as exc:
        log(f"nikto failed: {exc}")
        return []

    items: list[NiktoItem] = []
    for line in (proc.stdout or "").splitlines():
        if not _NIKTO_INTERESTING.match(line):
            continue
        body = line[2:].strip()
        if not body or body.startswith(("Target IP", "Target Hostname", "Target Port")):
            continue
        if body.startswith(("Start Time", "End Time", "host(s) tested", "Server:")):
            continue
        if body.lower().startswith(("no cgi directories", "root page / redirects", "0 item(s) reported")):
            continue
        # Metadata, not findings: "Platform: Linux/Unix", "SSL Info: Subject: ..."
        if body.startswith(("Platform:", "SSL Info:")):
            continue
        # Trailing summary: "7948 requests: 0 error(s) and 2 item(s) reported on remote host"
        if _NIKTO_SUMMARY.search(body):
            continue
        items.append(NiktoItem(target=target, message=body))
    log(f"nikto: {len(items)} item(s) for {target.url}")
    return items


def combine_web(
    hosts,
    log: LogFn | None = None,
    run_nikto: bool = True,
    max_time: int = 240,
    max_nikto_targets: int = 8,
):
    """Run the web phase. Returns (fingerprints, nikto items).

    whatweb is cheap and runs on every endpoint. nikto is slow and sequential,
    so it is capped — a range with forty web servers would otherwise turn one
    scan into an hour of HTTP probing.
    """
    targets = build_targets(hosts)
    fingerprints: list[WebResult] = []
    items: list[NiktoItem] = []
    for target in targets:
        fingerprints.append(whatweb(target, log))
    if run_nikto:
        budget = targets[:max_nikto_targets]
        if len(targets) > len(budget):
            log(
                f"nikto: covering {len(budget)} of {len(targets)} endpoint(s) — "
                "the rest were fingerprinted only"
            )
        for target in budget:
            items.extend(nikto(target, log, max_time=max_time))
    return fingerprints, items
