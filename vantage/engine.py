"""Scan orchestration.

The engine runs the phases a strategy declares, in canonical order, and degrades
gracefully: if the vuln phase is killed for overrunning its budget, the scan
still produces a report that *says so*, rather than quietly looking clean.

Progress is reported, never printed. Events:

    phase        {key, label, index, total, started}
    phase_done   {key, status, note, progress, duration_s}
    log          {message}
    warning      {message}
    asset        {host, port, protocol, hosts, ports}   <- live, per open port
    progress     {message, progress}
    finding      {finding dict}
    done         {full result dict}
"""

from __future__ import annotations

import datetime as dt
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from . import __version__, analyzer, nmap, tlscheck, webcheck
from .config import PHASE_LABELS, PHASE_ORDER, Limits, Profile, get_profile
from .models import Finding, Host, summarise
from .scope import Guard

EventFn = Callable[[str, dict], None]

#: nmap -v writes this to stdout the moment a port is found.
DISCOVERED_PORT = re.compile(r"^Discovered open port (\d+)/(\w+) on (\S+)")
#: "Nmap scan report for host.lan (10.0.0.5)" or "Nmap scan report for 10.0.0.5"
HOST_REPORT = re.compile(r"^Nmap scan report for (?:.*\()?([0-9a-fA-F:.]+)\)?\s*$")


def new_scan_id() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


@dataclass
class ScanResult:
    scan_id: str
    target: str
    profile: str
    guard: Guard
    started: str
    finished: str = ""
    duration_s: float = 0.0
    status: str = "running"
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    coverage: list[str] = field(default_factory=list)
    phases: list[dict[str, Any]] = field(default_factory=list)
    fingerprints: list[dict[str, Any]] = field(default_factory=list)
    tls: list[dict[str, Any]] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)
    strategy: dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> dict[str, Any]:
        return summarise(self.findings)

    @property
    def open_port_count(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "profile": self.profile,
            "strategy": self.strategy,
            "started": self.started,
            "finished": self.finished,
            "duration_s": round(self.duration_s, 1),
            "status": self.status,
            "guard": self.guard.to_dict(),
            "summary": self.summary,
            "hosts": [h.to_dict() for h in self.hosts],
            "findings": [f.to_dict() for f in self.findings],
            "warnings": self.warnings,
            "errors": self.errors,
            "coverage": self.coverage,
            "logs": self.logs,
            "phases": self.phases,
            "fingerprints": self.fingerprints,
            "tls": self.tls,
            "assets": self.assets,
            "tool_versions": self.tool_versions,
            "vantage_version": __version__,
        }


class Engine:
    def __init__(
        self,
        guard: Guard,
        profile: str | Profile = "standard",
        limits: Limits | None = None,
        emit: EventFn | None = None,
        dry_run: bool = False,
    ) -> None:
        self.guard = guard
        self.profile = get_profile(profile) if isinstance(profile, str) else profile
        self.limits = limits or Limits()
        self.emit = emit or (lambda _e, _p: None)
        self.dry_run = dry_run
        self.result = ScanResult(
            scan_id=new_scan_id(),
            target=guard.target,
            profile=self.profile.name,
            guard=guard,
            started=dt.datetime.now().isoformat(timespec="seconds"),
            strategy=self.profile.to_dict(),
        )
        self._phase_index = 0
        self._phases: list[str] = []
        self._phase_started: dict[str, float] = {}

        # live state, shared with the front ends through `asset` events
        self._assets: dict[tuple[str, int], dict[str, Any]] = {}
        self._hosts_seen: set[str] = set()

        # phase outputs
        self._hosts: list[Host] = []
        self._tls: list[Any] = []
        self._fpr: list[Any] = []
        self._nikto: list[Any] = []
        self._tls_covered = False
        self._web_covered = False

    # -- event plumbing ---------------------------------------------------

    def log(self, message: str) -> None:
        stamp = dt.datetime.now().strftime("%H:%M:%S")
        line = f"{stamp}  {message}"
        self.result.logs.append(line)
        self.emit("log", {"message": line})

    def _start_phase(self, key: str) -> None:
        self._phase_index += 1
        self._phase_started[key] = time.monotonic()
        entry = {
            "key": key,
            "label": PHASE_LABELS.get(key, key),
            "index": self._phase_index,
            "total": len(self._phases),
            "status": "running",
            "started": dt.datetime.now().isoformat(timespec="seconds"),
        }
        self.result.phases.append(entry)
        self.emit("phase", entry)

    def _end_phase(self, key: str, status: str = "done", note: str = "") -> None:
        duration = round(time.monotonic() - self._phase_started.get(key, time.monotonic()), 1)
        for entry in reversed(self.result.phases):
            if entry["key"] == key and entry["status"] == "running":
                entry["status"] = status
                entry["note"] = note
                entry["duration_s"] = duration
                entry["finished"] = dt.datetime.now().isoformat(timespec="seconds")
                break
        self.emit(
            "phase_done",
            {
                "key": key,
                "status": status,
                "note": note,
                "duration_s": duration,
                "progress": self.percent(),
            },
        )

    def percent(self) -> int:
        if not self._phases:
            return 0
        done = sum(
            1 for p in self.result.phases if p["status"] in ("done", "skipped", "failed")
        )
        return int(100 * done / len(self._phases))

    # -- live assets ------------------------------------------------------

    def _on_tool_progress(self, phase: str, line: str) -> None:
        text = line.strip()
        match = DISCOVERED_PORT.match(text)
        if match:
            port, proto, host = int(match.group(1)), match.group(2), match.group(3)
            key = (host, port)
            if key not in self._assets:
                self._hosts_seen.add(host)
                self._assets[key] = {
                    "host": host,
                    "port": port,
                    "protocol": proto,
                    "hosts": len(self._hosts_seen),
                    "ports": len(self._assets) + 1,
                }
                self.emit("asset", dict(self._assets[key]))
        else:
            host_match = HOST_REPORT.match(text)
            if host_match:
                host = host_match.group(1)
                if host not in self._hosts_seen:
                    self._hosts_seen.add(host)
                    self.emit("host", {"host": host, "hosts": len(self._hosts_seen)})
        self.emit("progress", {"message": line, "progress": self.percent()})

    # -- plan -------------------------------------------------------------

    def plan(self) -> list[str]:
        """Turn the strategy into the concrete phase list for this target."""
        wanted = [p for p in PHASE_ORDER if p in self.profile.phases]

        # Discovery is governed by the strategy's policy rather than the phase
        # list, so any port-scanning strategy can ping-sweep a range first.
        run_discovery = (
            self.profile.discovery == "always"
            or (
                self.profile.discovery == "auto"
                and self.profile.scans_ports
                and self.guard.host_estimate > 1
            )
        )
        if run_discovery and "discover" not in wanted:
            wanted.insert(0, "discover")
        elif not run_discovery and "discover" in wanted:
            wanted.remove("discover")

        if "ports" not in wanted:
            # nothing downstream can run without ports
            wanted = [p for p in wanted if p not in ("services", "vuln", "web", "tls")]
        if not wanted:
            wanted = ["discover"]

        phases = wanted + ["analyse"]
        self._phases = phases
        return phases

    # -- main --------------------------------------------------------------

    def run(self) -> ScanResult:
        t0 = time.monotonic()
        self.plan()
        self.result.tool_versions = {
            "vantage": __version__,
            "nmap": nmap.nmap_version() or "missing",
            "nikto": "present" if webcheck.have("nikto") else "missing",
            "whatweb": "present" if webcheck.have("whatweb") else "missing",
            "openssl": "present" if tlscheck.have_openssl() else "missing",
            "python": ".".join(map(str, __import__("sys").version_info[:3])),
        }
        self.log(
            f"vantage {__version__} · target {self.guard.target} "
            f"· strategy {self.profile.name} ({self.profile.description}) "
            f"· scope {self.guard.scope.name}"
        )
        for warning in self.guard.warnings:
            self.warnings_append(warning)

        if not nmap.have_binary("nmap"):
            self.result.status = "failed"
            self.result.errors.append("nmap is not installed — nothing can be scanned")
            self.result.finished = dt.datetime.now().isoformat(timespec="seconds")
            self.emit("done", self.result.to_dict())
            return self.result

        if self.dry_run:
            for phase in self._phases:
                self.log(f"dry-run: would run {PHASE_LABELS.get(phase, phase)}")
            self.result.status = "dry-run"
            self.result.duration_s = time.monotonic() - t0
            self.result.finished = dt.datetime.now().isoformat(timespec="seconds")
            self.emit("done", self.result.to_dict())
            return self.result

        runner = nmap.NmapRunner(
            self.guard,
            self.profile,
            self.limits,
            log=self.log,
            progress=self._on_tool_progress,
        )

        handlers = {
            "discover": self._phase_discover,
            "ports": self._phase_ports,
            "services": self._phase_services,
            "vuln": self._phase_vuln,
            "web": self._phase_web,
            "tls": self._phase_tls,
        }

        try:
            for key in self._phases:
                if key == "analyse":
                    self._phase_analyse()
                    continue
                self._start_phase(key)
                try:
                    note = handlers[key](runner)
                    self._end_phase(key, "done", note or "")
                except _SkipPhase as skip:
                    self._end_phase(key, "skipped", str(skip))
                except (nmap.NmapTimeout, nmap.NmapError) as exc:
                    self._fail_phase(key, str(exc))
                    if key == "ports":
                        self.result.status = "partial"
                        raise _StopScan(str(exc)) from None
                    if key == "vuln":
                        self.result.warnings.append(
                            "The NSE vulnerability phase did not finish; its results are incomplete."
                        )
                except _StopScan:
                    raise
                except Exception as exc:  # noqa: BLE001 - one tool must not kill the scan
                    self._fail_phase(key, f"{type(exc).__name__}: {exc}")

            if self.result.status == "running":
                self.result.status = "complete"

        except _StopScan as exc:
            self.result.errors.append(str(exc))
            self.result.status = "failed"
        except Exception as exc:  # noqa: BLE001 - report, never crash the caller
            self.result.errors.append(f"{type(exc).__name__}: {exc}")
            self.result.status = "failed"
            self.log(f"scan aborted: {type(exc).__name__}: {exc}")
        finally:
            self.result.warnings.extend(
                w for w in getattr(runner, "warnings", []) if w not in self.result.warnings
            )
            self.result.assets = sorted(
                self._assets.values(), key=lambda a: (a["host"], a["port"])
            )
            self.result.duration_s = time.monotonic() - t0
            self.result.finished = dt.datetime.now().isoformat(timespec="seconds")
            self.emit("done", self.result.to_dict())
        return self.result

    # -- phases ------------------------------------------------------------

    def _live(self) -> list[Host]:
        return [h for h in self._hosts if h.open_ports]

    def _phase_discover(self, runner: nmap.NmapRunner) -> str:
        try:
            self._hosts = runner.discover()
        except (nmap.NmapTimeout, nmap.NmapError) as exc:
            self.log(f"discovery failed: {exc} — continuing with an -Pn port scan")
            self._hosts = []
            if not self.profile.scans_ports:
                raise
            return "discovery failed; -Pn port scan follows"
        if not self._hosts:
            self.log("no hosts answered discovery")
            if self.profile.scans_ports:
                return "no hosts answered; -Pn port scan follows"
        return f"{len(self._hosts)} host(s) up"

    def _phase_ports(self, runner: nmap.NmapRunner) -> str:
        self._hosts = runner.port_scan(self._hosts or None)
        self.result.hosts = self._hosts
        live = len(self._live())
        if not live:
            self.log("no open TCP ports found in the scanned set")
            return "no open ports"
        return f"{self.result.open_port_count} port(s) on {live} host(s)"

    def _phase_services(self, runner: nmap.NmapRunner) -> str:
        live = self._live()
        if not live:
            raise _SkipPhase("no open ports")
        self._hosts = runner.service_scan(live)
        self.result.hosts = self._hosts
        return "banners collected"

    def _phase_vuln(self, runner: nmap.NmapRunner) -> str:
        live = self._live()
        if not live:
            raise _SkipPhase("no open ports")
        self._hosts = runner.vuln_scan(live)
        self.result.hosts = self._hosts
        return "NSE checks complete"

    def _phase_web(self, runner: nmap.NmapRunner) -> str:
        live = self._live()
        if not live:
            raise _SkipPhase("no open ports")
        self._fpr, self._nikto = webcheck.combine_web(
            live,
            log=self.log,
            run_nikto=webcheck.have("nikto"),
            max_time=min(180, self.limits.timeout.get("web", 1800)),
        )
        self._web_covered = True
        if not self._fpr:
            return "no web endpoints found"
        return f"{len(self._fpr)} endpoint(s)"

    def _phase_tls(self, runner: nmap.NmapRunner) -> str:
        live = self._live()
        if not live:
            raise _SkipPhase("no open ports")
        self._tls = tlscheck.inspect(live, log=self.log)
        self._tls_covered = True
        if not self._tls:
            return "no TLS endpoints found"
        return f"{len(self._tls)} endpoint(s)"

    def _phase_analyse(self) -> str:
        self._start_phase("analyse")
        self.result.hosts = self._hosts
        self.result.findings = analyzer.analyse(
            self._hosts,
            tls_results=self._tls,
            fingerprints=self._fpr,
            nikto_items=self._nikto,
            tls_covered=self._tls_covered,
        )
        self.result.coverage = analyzer.coverage_notes(
            self.profile,
            self._hosts,
            tls_covered=self._tls_covered,
            web_covered=self._web_covered,
        )
        if not self.profile.scans_ports:
            self.result.coverage.insert(
                0, "No port scanning was performed — this run only reports which addresses respond."
            )
        for finding in self.result.findings:
            self.emit("finding", finding.to_dict())
        self.result.fingerprints = [
            {
                "url": f.target.url,
                "host": f.target.host,
                "port": f.target.port,
                "server": f.server,
                "title": f.title,
                "tech": f.tech,
                "error": f.error,
            }
            for f in self._fpr
        ]
        self.result.tls = [t.__dict__ for t in self._tls]
        note = f"{len(self.result.findings)} finding(s)"
        self._end_phase("analyse", "done", note)
        return note

    # -- helpers -----------------------------------------------------------

    def warnings_append(self, text: str) -> None:
        if text and text not in self.result.warnings:
            self.result.warnings.append(text)
            self.emit("warning", {"message": text})

    def _fail_phase(self, key: str, message: str) -> None:
        self.result.errors.append(f"{PHASE_LABELS.get(key, key)}: {message}")
        self._end_phase(key, "failed", message[:200])
        self.log(f"{PHASE_LABELS.get(key, key)} failed: {message}")


class _StopScan(Exception):
    """Abort the whole scan (a phase it cannot proceed without has failed)."""


class _SkipPhase(Exception):
    """This phase has nothing to do for this target."""
