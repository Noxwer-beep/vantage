"""TLS inspection with the openssl CLI.

Checks performed per endpoint:
  * certificate subject/issuer/validity (expired, expiring soon)
  * self-signed / untrusted chain
  * negotiated protocol version (TLS 1.0/1.1 accepted = finding)
  * hostname mismatch on the presented certificate

Everything here is a read-only handshake — no traffic beyond the TLS setup.
"""

from __future__ import annotations

import datetime as _dt
import re
import shutil
import subprocess
from dataclasses import dataclass, field

from .config import TLS_PORTS

PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)


@dataclass
class TlsResult:
    host: str
    port: int
    server_name: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    days_left: int | None = None
    self_signed: bool = False
    verify_ok: bool | None = None
    verify_message: str = ""
    protocol: str = ""
    legacy_protocols: list[str] = field(default_factory=list)
    hostname_mismatch: bool = False
    error: str = ""
    cert_pem: str = ""

    @property
    def reachable(self) -> bool:
        return not self.error


def have_openssl() -> bool:
    return shutil.which("openssl") is not None


def _pem_to_details(pem: str) -> dict[str, str]:
    if not have_openssl():
        return {}
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates"],
            input=pem,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    out: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if line.startswith("subject="):
            out["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            out["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            out["not_before"] = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            out["not_after"] = line.split("=", 1)[1].strip()
    return out


def _parse_openssl_date(value: str) -> _dt.datetime | None:
    value = value.strip()
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT", "%Y%m%d%H%M%SZ"):
        try:
            return _dt.datetime.strptime(value, fmt).replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            continue
    return None


def probe(host: str, port: int, server_name: str = "", timeout: int = 15) -> TlsResult:
    res = TlsResult(host=host, port=port, server_name=server_name)
    if not have_openssl():
        res.error = "openssl not installed"
        return res

    sni = server_name or host
    cmd = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", sni,
        "-showcerts",
    ]
    try:
        proc = subprocess.run(
            cmd, input="", capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        res.error = "handshake timed out"
        return res
    except OSError as exc:
        res.error = f"openssl failed: {exc}"
        return res

    out = (proc.stdout or "") + (proc.stderr or "")
    if "BEGIN CERTIFICATE" not in out:
        res.error = _first_error(out) or "no certificate presented"
        return res

    match = PEM_RE.search(out)
    if match:
        res.cert_pem = match.group(0)
        details = _pem_to_details(res.cert_pem)
        res.subject = details.get("subject", "")
        res.issuer = details.get("issuer", "")
        res.not_before = details.get("not_before", "")
        res.not_after = details.get("not_after", "")
        if res.not_after:
            when = _parse_openssl_date(res.not_after)
            if when:
                res.days_left = (when - _dt.datetime.now(_dt.timezone.utc)).days
        res.self_signed = bool(res.subject and res.subject == res.issuer)

    proto = re.search(r"^\s*Protocol\s*:\s*(\S+)", out, re.MULTILINE)
    if proto:
        res.protocol = proto.group(1)
    else:
        # OpenSSL 3 moved the summary into 'New, TLSv1.3, Cipher is ...'
        alt = re.search(r"New,\s*(TLSv[\d.]+|[A-Za-z0-9]+),\s*Cipher", out)
        if alt:
            res.protocol = alt.group(1)

    verify = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)", out)
    if verify:
        res.verify_ok = verify.group(1) == "0"
        res.verify_message = verify.group(2).strip()

    cn = ""
    cn_match = re.search(r"Subject:\s*(?:.*?)?CN\s*=\s*([^,/\n]+)", res.subject or out)
    if cn_match:
        cn = cn_match.group(1).strip()
    san = re.findall(r"DNS:([^,\s]+)", out)
    if cn:
        names = {cn.lower(), *[s.lower() for s in san]}
        target = sni.lower()
        if target not in names and not any(
            n.startswith("*.") and target.endswith(n[1:]) for n in names
        ):
            res.hostname_mismatch = True
    return res


def _first_error(out: str) -> str:
    for line in out.splitlines():
        low = line.lower()
        if any(k in low for k in ("connect:errno", "handshake failure", "wrong version", "no peer certificate", "alert")):
            return line.strip()[:160]
    return ""


def legacy_protocols(host: str, port: int, server_name: str = "", timeout: int = 12) -> list[str]:
    """Return which deprecated TLS/SSL versions the endpoint still accepts."""
    if not have_openssl():
        return []
    sni = server_name or host
    accepted: list[str] = []
    attempts = [
        ("TLS 1.0", ["-tls1"]),
        ("TLS 1.1", ["-tls1_1"]),
    ]
    for label, flags in attempts:
        cmd = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-servername", sni,
            *flags,
            "-cipher", "DEFAULT@SECLEVEL=0",
        ]
        try:
            proc = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            continue
        out = (proc.stdout or "") + (proc.stderr or "")
        if "BEGIN CERTIFICATE" in out and "alert" not in out.lower():
            accepted.append(label)
    return accepted


def inspect(hosts, log=None) -> list[TlsResult]:
    """Probe TLS on every open TLS-ish port plus any 'ssl' service."""
    log = log or (lambda _m: None)
    results: list[TlsResult] = []
    seen: set[tuple[str, int]] = set()
    for host in hosts:
        for port in host.open_ports:
            name = (port.service or "").lower()
            if not (port.number in TLS_PORTS or "ssl" in name or "https" in name or "tls" in name):
                continue
            if (host.address, port.number) in seen:
                continue
            seen.add((host.address, port.number))
            sni = host.hostname or ""
            res = probe(host.address, port.number, sni)
            if not res.reachable:
                log(f"tls: {host.address}:{port.number} — {res.error}")
                continue
            res.legacy_protocols = legacy_protocols(host.address, port.number, sni)
            log(
                f"tls: {host.address}:{port.number} {res.protocol} "
                f"{'self-signed' if res.self_signed else 'ca-signed'}"
                + (f", {res.days_left}d left" if res.days_left is not None else "")
            )
            results.append(res)
    return results
