"""nmap invocation and XML parsing.

We shell out to nmap and parse `-oX -` ourselves instead of pulling in a
wrapper library: fewer moving parts, and the XML schema is stable.

Safety notes encoded here:
  * unprivileged runs fall back to a TCP connect scan (-sT) automatically;
  * `--script-args unsafe=1` is never passed — several NSE scripts can crash
    or wedge embedded services;
  * every invocation has a wall-clock timeout and is killed if it overruns.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .config import Limits, Profile, get_profile
from .models import Host, Port
from .scope import Guard

LogFn = Callable[[str], None]
ProgressFn = Callable[[str, str], None]


class NmapError(RuntimeError):
    pass


class NmapTimeout(NmapError):
    pass


@dataclass
class NmapRun:
    args: list[str]
    xml: str
    stderr: str
    returncode: int
    hosts: list[Host] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def have_binary(name: str) -> bool:
    return shutil.which(name) is not None


def is_privileged() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover - windows
        return False


def nmap_version() -> str | None:
    if not have_binary("nmap"):
        return None
    try:
        out = subprocess.run(
            ["nmap", "--version"], capture_output=True, text=True, timeout=20
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"^Nmap version (\S+)", out, re.MULTILINE)
    return m.group(1) if m else None


# ---------------------------------------------------------------- parsing

def _text(node: ET.Element | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.strip()


def parse_nmap_xml(xml: str) -> tuple[list[Host], list[str]]:
    """Parse nmap XML into Host objects. Returns (hosts, warnings)."""
    warnings: list[str] = []
    hosts: list[Host] = []
    if not xml or not xml.strip():
        return hosts, warnings
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise NmapError(f"nmap produced unparsable XML: {exc}") from None

    for host_el in root.findall("host"):
        status = host_el.find("status")
        state = status.get("state", "unknown") if status is not None else "unknown"
        address = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") in ("ipv4", "ipv6"):
                address = addr_el.get("addr", "")
                break
        if not address:
            continue
        hostname = ""
        for hn in host_el.findall("hostnames/hostname"):
            hostname = hn.get("name", "")
            if hn.get("type") == "user":
                break

        host = Host(address=address, hostname=hostname, state=state)

        for os_match in host_el.findall("os/osmatch"):
            host.os_matches.append(
                {
                    "name": os_match.get("name", ""),
                    "accuracy": os_match.get("accuracy", ""),
                }
            )

        for port_el in host_el.findall("ports/port"):
            st = port_el.find("state")
            svc = port_el.find("service")
            port = Port(
                number=int(port_el.get("portid", "0")),
                protocol=port_el.get("protocol", "tcp"),
                state=st.get("state", "unknown") if st is not None else "unknown",
                reason=st.get("reason", "") if st is not None else "",
                service=svc.get("name", "") if svc is not None else "",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
                extrainfo=svc.get("extrainfo", "") if svc is not None else "",
            )
            for script in port_el.findall("script"):
                port.scripts[script.get("id", "unknown")] = _text(script)
            host.ports.append(port)

        for script in host_el.findall("hostscript/script"):
            host.scripts[script.get("id", "unknown")] = _text(script)

        if state != "up" and not host.ports:
            continue
        hosts.append(host)

    for runstats in root.findall("runstats"):
        finished = runstats.find("finished")
        if finished is not None:
            exit_reason = finished.get("exit", "")
            if exit_reason and exit_reason not in ("success", ""):
                warnings.append(f"nmap finished with exit reason: {exit_reason}")

    return hosts, warnings


# ---------------------------------------------------------------- runner

class NmapRunner:
    """Builds and executes nmap commands for one authorised target set."""

    def __init__(
        self,
        guard: Guard,
        profile: Profile | str = "standard",
        limits: Limits | None = None,
        log: LogFn | None = None,
        progress: ProgressFn | None = None,
    ) -> None:
        self.guard = guard
        self.profile = get_profile(profile) if isinstance(profile, str) else profile
        self.limits = limits or Limits()
        self.log = log or (lambda _m: None)
        self.progress = progress or (lambda _p, _m: None)
        self._privileged = is_privileged()
        self.warnings: list[str] = []

    # -- command assembly -------------------------------------------------

    def base_args(self, phase: str) -> list[str]:
        # No `-oX -`: sending XML to stdout makes nmap suppress every progress
        # line, which leaves nothing to stream. The XML goes to a temp file
        # instead (see `_run`) and stdout carries the live output.
        args = ["nmap", "--no-stylesheet"]
        if phase == "discovery":
            args += ["-sn", "-PE", "-PS22,80,443", "-PA80,443"]
        else:
            scan_type = "-sS" if self._privileged else "-sT"
            args += [scan_type]
            if scan_type == "-sS":
                self.log("privileged: using SYN scan (-sS)")
        args += [f"-T{self.profile.timing}"]
        args += ["--max-retries", "2", "--max-rtt-timeout", "500ms", "--initial-rtt-timeout", "300ms"]
        if phase != "discovery":
            args += ["--max-hostgroup", str(self.limits.hostgroup)]
        args += ["-v"]
        return args

    def _targets(self) -> list[str]:
        """Pass networks where possible so nmap can do its own expansion."""
        if self.guard.networks:
            return list(self.guard.networks)
        return list(self.guard.addresses)

    def _run(
        self,
        args: list[str],
        phase: str,
        timeout: int | None = None,
    ) -> NmapRun:
        if not have_binary("nmap"):
            raise NmapError("nmap is not installed or not on PATH")
        timeout = timeout or self.limits.timeout.get(phase, 3600)

        handle, xml_path = tempfile.mkstemp(prefix="vantage-nmap-", suffix=".xml")
        os.close(handle)
        run_args = args + ["-oX", xml_path]
        self.log("nmap " + " ".join(args[1:]))

        try:
            proc = subprocess.Popen(
                run_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            out_lines: list[str] = []
            err_lines: list[str] = []

            def pump_out() -> None:
                """nmap's human output is on stdout once XML goes to a file."""
                assert proc.stdout is not None
                for line in proc.stdout:
                    line = line.rstrip()
                    if not line:
                        continue
                    out_lines.append(line)
                    if (
                        line.startswith("Discovered open port")
                        or line.startswith("Nmap scan report for")
                        or ("Scanning " in line and "[host" in line)
                    ):
                        self.progress(phase, line)

            def pump_err() -> None:
                assert proc.stderr is not None
                for line in proc.stderr:
                    line = line.rstrip()
                    if line:
                        err_lines.append(line)

            out_thread = threading.Thread(target=pump_out, daemon=True)
            err_thread = threading.Thread(target=pump_err, daemon=True)
            out_thread.start()
            err_thread.start()
            try:
                out_thread.join(timeout)
                if out_thread.is_alive():
                    proc.kill()
                    raise NmapTimeout(
                        f"nmap exceeded the {timeout}s budget during the {phase} phase and was killed"
                    )
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                raise NmapTimeout(f"nmap did not exit during the {phase} phase") from None
            finally:
                err_thread.join(timeout=3)

            stdout = ""
            try:
                stdout = Path(xml_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                stdout = ""
            stderr = "\n".join(out_lines + err_lines)
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass
        warnings: list[str] = []
        for line in stderr.splitlines():
            if line.startswith(("WARNING:", "QUITTING:", "nmap: ")):
                warnings.append(line)

        run = NmapRun(
            args=args,
            xml=stdout or "",
            stderr=stderr,
            returncode=proc.returncode,
            warnings=warnings,
        )
        if proc.returncode not in (0, 1):
            raise NmapError(
                f"nmap exited {proc.returncode} during {phase}: {stderr.strip()[-400:] or 'no output'}"
            )
        return run

    # -- phases -----------------------------------------------------------

    def discover(self) -> list[Host]:
        args = self.base_args("discovery") + self._targets()
        run = self._run(args, "discovery", timeout=self.limits.timeout["discovery"])
        hosts, warnings = parse_nmap_xml(run.xml)
        self.warnings.extend(run.warnings + warnings)
        up = [h for h in hosts if h.state == "up"]
        self.log(f"discovery: {len(up)} host(s) up")
        return up

    def port_scan(self, live_hosts: Sequence[Host] | None = None) -> list[Host]:
        args = self.base_args("ports") + self.profile.ports.split()
        if live_hosts:
            args += ["-Pn", *[h.address for h in live_hosts]]
        else:
            args += ["-Pn", *self._targets()]
        run = self._run(args, "ports", timeout=self.limits.timeout["ports"])
        hosts, warnings = parse_nmap_xml(run.xml)
        self.warnings.extend(run.warnings + warnings)
        hosts = [h for h in hosts if h.open_ports] or hosts
        self.log(f"ports: {sum(len(h.open_ports) for h in hosts)} open port(s) on {len(hosts)} host(s)")
        return hosts

    def service_scan(self, hosts: Sequence[Host]) -> list[Host]:
        if not hosts:
            return []
        if not self.profile.version_detection:
            return list(hosts)
        args = self.base_args("services")
        intensity = "7" if self.profile.name == "deep" else "5"
        args += ["-sV", "--version-intensity", intensity]
        # Only probe ports we already know are open — that is faster *and*
        # quieter than re-scanning the whole range.
        args += self._port_selector(hosts)
        args += ["-Pn", *[h.address for h in hosts]]
        run = self._run(args, "services", timeout=self.limits.timeout["services"])
        scanned, warnings = parse_nmap_xml(run.xml)
        self.warnings.extend(run.warnings + warnings)
        # merge banners into the hosts we already have, preserving port state
        by_addr = {h.address: h for h in scanned}
        for host in hosts:
            fresh = by_addr.get(host.address)
            if not fresh:
                continue
            for port in fresh.ports:
                existing = host.port(port.number, port.protocol)
                if existing is None:
                    if port.state == "open":
                        host.ports.append(port)
                    continue
                existing.service = port.service or existing.service
                existing.product = port.product or existing.product
                existing.version = port.version or existing.version
                existing.extrainfo = port.extrainfo or existing.extrainfo
            if not host.hostname and fresh.hostname:
                host.hostname = fresh.hostname
        self.log("services: banners collected")
        return list(hosts)

    def _port_selector(self, hosts: Sequence[Host]) -> list[str]:
        """One -p argument covering every open TCP port across the host set."""
        all_ports = sorted(
            {p.number for host in hosts for p in host.open_ports if p.protocol == "tcp"}
        )
        if not all_ports:
            return []
        return ["-p", ",".join(str(n) for n in all_ports)]

    def vuln_scan(self, hosts: Sequence[Host]) -> list[Host]:
        if not hosts or not self.profile.vuln_scripts:
            return list(hosts)
        args = self.base_args("vuln")
        # 90 seconds per script: enough for a slow HTTP check, short enough that
        # a tarpitted port cannot stall the phase. Measured on a host with two
        # HTTP services, the whole vuln phase lands near two minutes.
        args += ["--script", "vuln", "--script-timeout", "90s"]
        port_args = self._port_selector(hosts)
        args += port_args
        args += ["-Pn", *[h.address for h in hosts]]
        run = self._run(args, "vuln", timeout=self.limits.timeout["vuln"])
        scanned, warnings = parse_nmap_xml(run.xml)
        self.warnings.extend(run.warnings + warnings)
        by_addr = {h.address: h for h in scanned}
        for host in hosts:
            fresh = by_addr.get(host.address)
            if not fresh:
                continue
            for port in fresh.ports:
                existing = host.port(port.number, port.protocol)
                if existing is not None:
                    existing.scripts.update(port.scripts)
            host.scripts.update(fresh.scripts)
        self.log("vuln: NSE vulnerability checks complete")
        return list(hosts)


def quick_probe(host: str, port: int, timeout: float = 3.0) -> bool:
    """Single TCP connect, used to double-check an open port before reporting."""
    import socket as _s

    try:
        with _s.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
