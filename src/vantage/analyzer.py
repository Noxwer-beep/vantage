"""Analysis: observations in, defensible findings out.

The rule this module lives by: **never claim more than the evidence supports.**

  * An NSE script that prints "State: VULNERABLE" is `confirmed` — nmap ran a
    check and got a positive answer.
  * A Nikto line is `possible` — Nikto is a heuristic scanner and its output
    has historically produced false positives.
  * An end-of-life banner is `possible` at best — the banner is the remote
    service's own claim, and backported security fixes make banners lie.
  * A well-known risky service being reachable is `confirmed` as an *exposure*,
    which is a fact about reachability, not about exploitability.

Each finding carries the reasoning in `detail`, and the report renders the
confidence next to the severity so a reader can tell them apart.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Sequence

from .models import Finding, Host, Port

KNOWLEDGE = Path(__file__).parent / "knowledge"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
CVSS_RE = re.compile(r"CVSS(?:v[23])?\s*(?:score)?\s*[:=]?\s*(\d{1,2}\.\d)")


@lru_cache(maxsize=1)
def exposure_kb() -> tuple[dict, dict]:
    data = json.loads((KNOWLEDGE / "ports.json").read_text(encoding="utf-8"))
    return data.get("services", {}), data.get("port_fallback", {})


@lru_cache(maxsize=1)
def eol_rules() -> list[dict]:
    data = json.loads((KNOWLEDGE / "eol.json").read_text(encoding="utf-8"))
    return data.get("rules", [])


# ---------------------------------------------------------------- NSE

#: Curated severity/title for NSE script ids. Anything not listed is graded
#: from its own output text (see `_grade_nse`).
NSE_META: dict[str, tuple[str, str, str]] = {
    # (severity, title, category)
    "smb-vuln-ms17-010": ("critical", "SMBv1 EternalBlue (MS17-010) reported vulnerable", "cve"),
    "smb-vuln-ms08-067": ("critical", "Windows Server service RCE (MS08-067) reported vulnerable", "cve"),
    "smb-vuln-conficker": ("critical", "Conficker/MS08-067 infection vector reported", "cve"),
    "smb-vuln-regsvc-dos": ("medium", "SMB service denial-of-service condition reported", "cve"),
    "smb-vuln-webexec": ("high", "SMB web execution interface reachable", "cve"),
    "smb-vuln-cve2009-3103": ("high", "SMB2 negotiation RCE (CVE-2009-3103) reported", "cve"),
    "smb2-vuln-uptime": ("info", "SMB2 uptime recovered (patch-level inference possible)", "info"),
    "smb-security-mode": ("info", "SMB security mode settings parsed", "info"),
    "ssl-heartbleed": ("critical", "OpenSSL Heartbleed (CVE-2014-0160) reported vulnerable", "cve"),
    "ssl-poodle": ("medium", "SSLv3 POODLE (CVE-2014-3566) reported", "cve"),
    "ssl-ccs-injection": ("high", "OpenSSL CCS injection (CVE-2014-0224) reported", "cve"),
    "ssl-dh-params": ("medium", "Weak Diffie-Hellman parameters (Logjam-style) reported", "crypto"),
    "ssl-known-key": ("medium", "Server key is on a public known-key list", "crypto"),
    "ssl-cert-intaddr": ("low", "Certificate exposes internal hostnames or addresses", "crypto"),
    "ssl-enum-ciphers": ("info", "Cipher suite inventory collected", "info"),
    "ssl-date": ("info", "TLS clock skew check", "info"),
    "ssl-cert": ("info", "Certificate details parsed", "info"),
    "http-shellshock": ("critical", "Shellshock (CVE-2014-6271) reported vulnerable", "cve"),
    "http-vuln-cve2017-5638": ("critical", "Apache Struts2 RCE (CVE-2017-5638) reported vulnerable", "cve"),
    "http-vuln-cve2014-3704": ("critical", "Drupal SQL injection (CVE-2014-3704) reported vulnerable", "cve"),
    "http-vuln-cve2015-1635": ("critical", "Windows HTTP.sys RCE (CVE-2015-1635) reported vulnerable", "cve"),
    "http-vuln-cve2012-1823": ("critical", "PHP-CGI argument injection (CVE-2012-1823) reported vulnerable", "cve"),
    "http-vuln-cve2011-3368": ("high", "Apache reverse-proxy bypass (CVE-2011-3368) reported", "cve"),
    "http-vuln-cve2013-0156": ("critical", "Ruby on Rails XML deserialisation (CVE-2013-0156) reported", "cve"),
    "http-vuln-cve2014-2126": ("high", "Cisco ASA vulnerability (CVE-2014-2126) reported", "cve"),
    "http-vuln-cve2010-0738": ("high", "JBoss JMX console access (CVE-2010-0738) reported", "cve"),
    "http-vuln-cve2011-3192": ("high", "Apache Range header DoS (CVE-2011-3192) reported", "cve"),
    "http-vuln-cve2012-1823": ("critical", "PHP-CGI RCE (CVE-2012-1823) reported", "cve"),
    "http-iis-webdav-vuln": ("high", "IIS WebDAV write access (CVE-2009-1535) reported", "cve"),
    "http-phpmyadmin-dir-traversal": ("high", "phpMyAdmin directory traversal reported", "cve"),
    "http-sql-injection": ("high", "SQL injection parameter reported by NSE", "web"),
    "http-stored-xss": ("medium", "Stored XSS vector reported by NSE", "web"),
    "http-dombased-xss": ("medium", "DOM-based XSS vector reported by NSE", "web"),
    "http-csrf": ("medium", "Form without anti-CSRF token reported", "web"),
    "http-trace": ("low", "HTTP TRACE method enabled", "web"),
    "http-put": ("medium", "HTTP PUT method accepted (WebDAV upload)", "web"),
    "http-methods": ("info", "HTTP methods enumerated", "info"),
    "ftp-anon": ("medium", "Anonymous FTP login permitted", "access"),
    "ftp-proftpd-backdoor": ("critical", "ProFTPD 1.3.3c backdoor (CVE-2010-4221) reported", "cve"),
    "ftp-vsftpd-backdoor": ("critical", "vsftpd 2.3.4 backdoor reported", "cve"),
    "ftp-vuln-cve2010-4221": ("high", "ProFTPD RCE (CVE-2010-4221) reported", "cve"),
    "rdp-vuln-ms12-020": ("critical", "RDP RCE (MS12-020) reported vulnerable", "cve"),
    "realvnc-auth-bypass": ("critical", "RealVNC authentication bypass reported", "cve"),
    "qconn-exec": ("critical", "QNX qconn command execution interface reachable", "exposure"),
    "supermicro-ipmi-conf": ("high", "Supermicro IPMI with default credentials reported", "access"),
    "stuxnet-detect": ("critical", "Stuxnet indicator found", "malware"),
    "mysql-empty-password": ("high", "MySQL accepts an empty password for root", "access"),
    "mysql-vuln-cve2012-2122": ("critical", "MySQL authentication bypass (CVE-2012-2123) reported", "cve"),
    "ms-sql-empty-password": ("high", "MSSQL accepts an empty password for sa", "access"),
    "msrpc-enum": ("info", "RPC endpoints enumerated", "info"),
    "nbstat": ("info", "NetBIOS name table read", "info"),
    "smb-os-discovery": ("info", "SMB operating system disclosure", "info"),
    "smb-enum-shares": ("info", "SMB shares enumerated", "info"),
    "ssh-auth-methods": ("info", "SSH authentication methods listed", "info"),
    "ssh-hostkey": ("info", "SSH host keys retrieved", "info"),
    "rpcinfo": ("info", "RPC services enumerated", "info"),
}

#: NSE scripts handled more precisely by `tlscheck`; skipped when that phase ran.
TLS_NSE = {"ssl-cert", "ssl-date", "ssl-enum-ciphers"}

_NOISE = re.compile(r"^(ERROR|Couldn't|failed|unknown|No response)", re.IGNORECASE)


def _grade_nse(script_id: str, output: str) -> tuple[str, str, str] | None:
    """Return (severity, title, category) or None when there is nothing to report."""
    meta = NSE_META.get(script_id)
    lowered = output.lower()

    state = ""
    m = re.search(r"state:\s*([a-z ]+)", lowered)
    if m:
        state = m.group(1).strip()

    negative = "not vulnerable" in lowered or state.startswith("not vulnerable")
    positive = "vulnerable" in lowered and not negative
    likely = "likely vulnerable" in lowered or state.startswith("likely")

    if meta:
        severity, title, category = meta
        # An informational script that also announces vulnerability is upgraded.
        if positive and severity == "info":
            return "high", title, "nse"
        return severity, title, category

    if positive:
        return ("high", f"NSE {script_id} reports a vulnerability indicator", "nse")
    if likely:
        return ("medium", f"NSE {script_id} reports a possible vulnerability", "nse")
    return None


def nse_findings(hosts: Sequence[Host], tls_covered: bool = False) -> list[Finding]:
    out: list[Finding] = []
    for host in hosts:
        for script_id, output in host.scripts.items():
            out.extend(_one_nse(host, script_id, output, port=None, tls_covered=tls_covered))
        for port in host.open_ports:
            for script_id, output in port.scripts.items():
                out.extend(_one_nse(host, script_id, output, port=port, tls_covered=tls_covered))
    return out


def _one_nse(host, script_id, output, port, tls_covered) -> list[Finding]:
    if not output or not output.strip():
        return []
    if _NOISE.match(output.strip()):
        return []
    if tls_covered and script_id in TLS_NSE:
        return []
    graded = _grade_nse(script_id, output)
    if graded is None:
        return []
    severity, title, category = graded

    confidence = "informational"
    lowered = output.lower()
    if "not vulnerable" in lowered and "state: not vulnerable" in lowered:
        return []
    if "likely vulnerable" in lowered or "state: likely vulnerable" in lowered:
        confidence = "likely"
    elif "state: vulnerable" in lowered or re.search(r"\bvulnerable\b", lowered):
        if "state: not vulnerable" not in lowered:
            confidence = "confirmed"
    if confidence == "informational" and severity in ("critical", "high", "medium"):
        confidence = "possible"

    title_clean = title
    cves = sorted(set(CVE_RE.findall(output)))
    cvss_match = CVSS_RE.search(output)
    cvss = float(cvss_match.group(1)) if cvss_match else None

    detail_parts = [f"nmap NSE script `{script_id}` reported this."]
    if confidence == "confirmed":
        detail_parts.append("The script returned a positive result, so treat it as real until proven otherwise.")
    elif confidence == "likely":
        detail_parts.append("The script's answer was 'likely vulnerable' — verify manually before reporting it as certain.")
    else:
        detail_parts.append("This is a configuration observation from the script output; no exploit was attempted.")

    return [
        Finding(
            title=title_clean,
            severity=severity,
            category=category,
            host=host.address,
            port=port.number if port else None,
            protocol=port.protocol if port else "tcp",
            service=(port.service if port else "") or "",
            evidence=_shorten(output, 900),
            detail=" ".join(detail_parts),
            remediation=_nse_remediation(script_id, category),
            references=[f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:4]],
            confidence=confidence,
            cvss=cvss,
            source=f"nmap:{script_id}",
            cves=cves[:6],
        )
    ]


def _nse_remediation(script_id: str, category: str) -> str:
    specific = {
        "smb-vuln-ms17-010": "Apply MS17-010, disable SMBv1, and block TCP 445 at segment boundaries.",
        "smb-vuln-ms08-067": "Apply MS08-067 or retire the host; it is far outside support.",
        "ssl-heartbleed": "Upgrade OpenSSL and reissue the certificate. Assume memory contents were exposed.",
        "ssl-poodle": "Disable SSLv3 entirely and prefer TLS 1.2+.",
        "ssl-ccs-injection": "Upgrade OpenSSL to a patched release.",
        "ssl-dh-params": "Regenerate DH parameters at 2048 bits or move to ECDHE suites.",
        "http-shellshock": "Patch bash on the web host and rotate any credentials stored on it.",
        "http-vuln-cve2017-5638": "Upgrade Struts2 to a patched release; block the Content-Type OGNL vector at the WAF as a stopgap.",
        "ftp-anon": "Disable anonymous FTP access and restrict upload directories.",
        "mysql-empty-password": "Set a strong root password and bind MySQL to the application subnet.",
        "ms-sql-empty-password": "Set a strong sa password and disable mixed-mode authentication where possible.",
        "http-trace": "Disable the TRACE method in the web server configuration.",
        "http-put": "Disable WebDAV/HTTP PUT unless it is required and authenticated.",
        "http-csrf": "Add anti-CSRF tokens to state-changing forms and set SameSite on session cookies.",
    }
    if script_id in specific:
        return specific[script_id]
    if category == "cve":
        return "Patch the affected software to a current release, then re-run this check to confirm the indicator is gone."
    if category == "web":
        return "Review the referenced finding with the application owner and confirm it manually before changing code."
    if category == "access":
        return "Remove or authenticate the access path; restrict it by source address if it must remain."
    return "Review the script output and decide with the system owner whether a change is needed."


# ---------------------------------------------------------------- exposure

def exposure_findings(hosts: Sequence[Host]) -> list[Finding]:
    services, fallback = exposure_kb()
    out: list[Finding] = []
    for host in hosts:
        for port in host.open_ports:
            entry = services.get((port.service or "").lower())
            if entry is None:
                key = fallback.get(str(port.number))
                entry = services.get(key) if key else None
            if entry is None:
                continue
            # An https listener is not "unencrypted HTTP".
            if port.service.lower() in ("http",) and port.number in (443, 8443, 9443):
                continue
            banner = port.banner
            evidence = f"{port.number}/{port.protocol} open · {port.label}"
            if banner:
                evidence += f" · banner: {banner}"
            out.append(
                Finding(
                    title=entry["title"],
                    severity=entry["severity"],
                    category="exposure",
                    host=host.address,
                    port=port.number,
                    protocol=port.protocol,
                    service=port.service,
                    evidence=evidence,
                    detail=entry["detail"]
                    + " This records reachability only — no exploit was attempted.",
                    remediation=entry["remediation"],
                    references=entry.get("refs", []),
                    confidence="confirmed",
                    source="exposure-kb",
                )
            )
    return out


# ---------------------------------------------------------------- versions

def _parse_version(text: str) -> tuple[int, ...] | None:
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[a-z](\d+))?", text or "")
    if not m:
        return None
    parts = [int(g) for g in m.groups()[:3] if g is not None]
    return tuple(parts) if parts else None


def _lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    width = max(len(a), len(b))
    a = a + (0,) * (width - len(a))
    b = b + (0,) * (width - len(b))
    return a < b


def version_findings(hosts: Sequence[Host]) -> list[Finding]:
    """Flag banners that sit below a curated end-of-life threshold."""
    out: list[Finding] = []
    for host in hosts:
        for port in host.open_ports:
            haystack = f"{port.product} {port.extrainfo}".lower()
            if not haystack.strip():
                continue
            for rule in eol_rules():
                if rule["match"] not in haystack:
                    continue
                version = _parse_version(port.version)
                if version is None:
                    continue
                if not _lt(version, tuple(rule["max_safe"])):
                    continue
                out.append(
                    Finding(
                        title=rule["title"],
                        severity=rule["severity"],
                        category="outdated-software",
                        host=host.address,
                        port=port.number,
                        protocol=port.protocol,
                        service=port.service,
                        evidence=f"{port.label} · full banner: {port.banner or port.product}",
                        detail=rule["detail"]
                        + " Version banners can be misleading when a distributor backports "
                        "fixes without changing the reported number, so confirm with the "
                        "owner before treating this as an open vulnerability.",
                        remediation=rule["remediation"],
                        references=rule.get("refs", []),
                        confidence="possible",
                        source="eol-table",
                    )
                )
    return out


# ---------------------------------------------------------------- web

NIKTO_RULES: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"(default|blank|empty)\s+(password|credential)", re.I), "high",
     "Default or empty credentials reported on a web interface", "access"),
    (re.compile(r"(sql injection|xss|cross.site scripting|remote (code|command) execution|arbitrary file)", re.I),
     "high", "Web application flaw reported by nikto", "web"),
    (re.compile(r"(\.git|\.svn|\.env|backup|\.bak|config|database dump|phpinfo)", re.I), "medium",
     "Sensitive file or backup exposed by the web server", "disclosure"),
    (re.compile(r"(directory indexing|directory listing|index of /|allows indexing)", re.I), "low",
     "Directory listing enabled", "misconfig"),
    (re.compile(r"(x-frame-options|content-security-policy|strict-transport-security|x-content-type-options|referrer-policy)", re.I),
     "low", "Security header missing", "headers"),
    (re.compile(r"(allowed http methods|put|delete|webdav|trace)", re.I), "medium",
     "Permissive HTTP method or WebDAV exposed", "misconfig"),
    (re.compile(r"(outdated|vulnerable|eol|end of life)", re.I), "medium",
     "Outdated component reported by nikto", "outdated-software"),
    (re.compile(r"(cookie|session).*(without|missing|no).*(httponly|secure|samesite)", re.I), "low",
     "Session cookie missing a protective flag", "headers"),
    (re.compile(r"(admin|login|manager|console|dashboard)", re.I), "low",
     "Administrative interface reachable", "exposure"),
]

HEADER_FIX = {
    "x-frame-options": "Add `X-Frame-Options: DENY` (or a CSP `frame-ancestors` directive).",
    "content-security-policy": "Define a Content-Security-Policy suited to the application's asset sources.",
    "strict-transport-security": "Add `Strict-Transport-Security` with a long max-age once HTTPS is enforced.",
    "x-content-type-options": "Add `X-Content-Type-Options: nosniff`.",
    "referrer-policy": "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
    "permissions-policy": "Add a `Permissions-Policy` limiting camera, microphone, geolocation and similar features.",
}

_HEADER_LABEL = {
    "x-frame-options": "X-Frame-Options",
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def web_findings(fingerprints, nikto_items) -> list[Finding]:
    """Turn nikto/whatweb output into findings.

    Missing security headers are aggregated per endpoint: five separate rows
    saying "X-Frame-Options missing", "CSP missing", ... is noise. One row
    listing all of them is something a reader can act on.
    """
    out: list[Finding] = []
    header_issues: dict[tuple[str, int, str], list[str]] = {}

    for item in nikto_items:
        message = item.message.lower()
        matched_header = None
        for header in HEADER_FIX:
            if header in message:
                matched_header = header
                break

        if matched_header:
            # HSTS on a plaintext listener is meaningless — the browser never
            # sees the header over HTTP anyway.
            if matched_header == "strict-transport-security" and item.target.scheme == "http":
                continue
            key = (item.target.host, item.target.port, item.target.url)
            header_issues.setdefault(key, []).append(matched_header)
            continue

        severity, title, category = "info", "Nikto observation", "web"
        for pattern, sev, ttl, cat in NIKTO_RULES:
            if pattern.search(item.message):
                severity, title, category = sev, ttl, cat
                break

        # "[600720] SimpleHTTP/0.6 appears to be outdated" — name the component
        # instead of reporting a vague "outdated component".
        outdated = re.search(r"(\S+)\s+appears to be outdated", item.message, re.IGNORECASE)
        if outdated:
            title = f"Outdated component: {outdated.group(1)}"
            category = "outdated-software"

        out.append(
            Finding(
                title=title,
                severity=severity,
                category=category,
                host=item.target.host,
                port=item.target.port,
                protocol="tcp",
                service="http",
                evidence=f"{item.target.url} — {_shorten(item.message, 300)}",
                detail="Reported by nikto's configuration review. Nikto is pattern-based; "
                       "each item should be confirmed by hand before it goes into a client report.",
                remediation="Review the finding in context; nikto reports can contain false positives.",
                references=sorted({f"https://nvd.nist.gov/vuln/detail/{c}" for c in item.cves}),
                confidence="possible",
                source="nikto",
                cves=item.cves,
            )
        )

    for (host, port, url), headers in header_issues.items():
        headers = sorted(set(headers))
        display = ", ".join(_HEADER_LABEL.get(h, h) for h in headers)
        fixes = "\n".join(f"· {_HEADER_LABEL.get(h, h)}: {HEADER_FIX[h]}" for h in headers)
        out.append(
            Finding(
                title=f"{len(headers)} security header(s) missing",
                severity="low",
                category="headers",
                host=host,
                port=port,
                protocol="tcp",
                service="http",
                evidence=f"{url} — missing: {display}",
                detail="These response headers are absent. Each one independently reduces the "
                       "browser's defences against clickjacking, MIME sniffing, referrer leakage "
                       "or mixed content. Individually minor, but they are cheap to add.",
                remediation=fixes,
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                    "https://infosec.mozilla.org/guidelines/web_security",
                ],
                confidence="possible",
                source="nikto",
            )
        )

    for fp in fingerprints:
        if fp.server:
            out.append(
                Finding(
                    title="Server banner discloses software and version",
                    severity="info",
                    category="information-disclosure",
                    host=fp.target.host,
                    port=fp.target.port,
                    service="http",
                    evidence=f"{fp.target.url} → {fp.server}",
                    detail="A precise server banner helps an attacker pick exploits. "
                           "This is a hardening note, not a vulnerability.",
                    remediation="Reduce the banner to a product name, or omit it.",
                    confidence="confirmed",
                    source="whatweb",
                )
            )
        for tech in fp.tech:
            if tech.lower() in ("php", "asp.net", "wordpress", "joomla", "drupal"):
                out.append(
                    Finding(
                        title=f"Web stack fingerprinted: {tech}",
                        severity="info",
                        category="information-disclosure",
                        host=fp.target.host,
                        port=fp.target.port,
                        service="http",
                        evidence=f"{fp.target.url} → {', '.join(fp.tech[:8])}",
                        detail="Technology fingerprint only. It matters for patch tracking, "
                               "and it is not on its own a weakness.",
                        remediation=f"Keep {tech} and its plugins on a supported release and track CVEs for the exact version.",
                        confidence="confirmed",
                        source="whatweb",
                    )
                )
                break
    return out


# ---------------------------------------------------------------- TLS

def tls_findings(results) -> list[Finding]:
    out: list[Finding] = []
    for r in results:
        if not r.reachable:
            continue
        base = dict(host=r.host, port=r.port, service="https", category="tls")
        cert_who = r.subject or "unknown subject"

        if r.days_left is not None and r.days_left < 0:
            out.append(Finding(
                title="TLS certificate expired",
                severity="high", evidence=f"{r.host}:{r.port} expired {abs(r.days_left)} day(s) ago ({r.not_after})",
                detail=f"The certificate presented ({cert_who}) is past its notAfter date. Clients will refuse or warn.",
                remediation="Renew the certificate and automate renewal (ACME) so this cannot recur.",
                confidence="confirmed", source="tls-probe", **base))
        elif r.days_left is not None and r.days_left <= 30:
            out.append(Finding(
                title=f"TLS certificate expires in {r.days_left} day(s)",
                severity="medium", evidence=f"{r.host}:{r.port} notAfter={r.not_after}",
                detail=f"The certificate ({cert_who}) expires soon.",
                remediation="Renew now; if renewal is manual, put a calendar reminder and an expiry alert in place.",
                confidence="confirmed", source="tls-probe", **base))

        if r.self_signed:
            out.append(Finding(
                title="TLS certificate is self-signed",
                severity="medium", evidence=f"{r.host}:{r.port} subject == issuer ({r.subject})",
                detail="A self-signed certificate cannot be validated by a client, so users are trained to click through warnings.",
                remediation="Issue a certificate from a trusted CA (internal PKI or public CA). Keep self-signed certs for lab use only.",
                confidence="confirmed", source="tls-probe", **base))

        if r.verify_ok is False and not r.self_signed:
            out.append(Finding(
                title="TLS certificate chain does not verify",
                severity="medium", evidence=f"{r.host}:{r.port} verify: {r.verify_message or 'failed'}",
                detail="The presented chain failed verification — an incomplete intermediate chain or an untrusted issuer.",
                remediation="Serve the full intermediate chain and confirm the root is trusted by clients.",
                confidence="confirmed", source="tls-probe", **base))

        if r.hostname_mismatch:
            out.append(Finding(
                title="TLS certificate does not match the hostname",
                severity="medium", evidence=f"{r.host}:{r.port} served {r.subject or 'unknown'}",
                detail="The certificate's subject/SAN does not cover the name being used, which produces browser warnings and can mask interception.",
                remediation="Reissue the certificate with a SAN covering every name served on this endpoint.",
                confidence="likely", source="tls-probe", **base))

        for proto in r.legacy_protocols:
            out.append(Finding(
                title=f"Deprecated {proto} accepted",
                severity="high", evidence=f"{r.host}:{r.port} completed a {proto} handshake",
                detail=f"The endpoint negotiated {proto}. These versions are deprecated by RFC 8996 and carry known structural weaknesses.",
                remediation="Disable TLS 1.0/1.1 and require TLS 1.2 or newer; re-test with an SSL Labs style scan afterwards.",
                references=["https://www.rfc-editor.org/rfc/rfc8996"],
                confidence="confirmed", source="tls-probe", **base))
    return out


# ---------------------------------------------------------------- misc

def _shorten(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse duplicates, keeping the most severe / most confident instance."""
    best: dict[str, Finding] = {}
    for f in findings:
        existing = best.get(f.key)
        if existing is None:
            best[f.key] = f
            continue
        if f.sort_key < existing.sort_key:
            # keep richer evidence from whichever had it
            if not f.evidence and existing.evidence:
                f.evidence = existing.evidence
            best[f.key] = f
        else:
            if not existing.evidence and f.evidence:
                existing.evidence = f.evidence
            if f.evidence and len(f.evidence) > len(existing.evidence):
                existing.evidence = f.evidence
    return sorted(best.values(), key=lambda f: f.sort_key)


def coverage_notes(profile, hosts, tls_covered: bool, web_covered: bool) -> list[str]:
    """What this scan did *not* do — printed with every report."""
    notes = [
        "TCP scanning only — UDP services (SNMP traps, mDNS, some VPNs) were not enumerated."
        if not getattr(profile, "udp", False) else "UDP scanning enabled.",
        "No authentication was attempted and no credentials were used.",
        "No exploit was executed; all vulnerability claims come from banner analysis and NSE scripts.",
    ]
    if not getattr(profile, "vuln_scripts", False):
        notes.append("NSE 'vuln' scripts were skipped in this profile — findings are exposure-level only.")
    if not tls_covered:
        notes.append("TLS endpoints were not inspected.")
    if not web_covered:
        notes.append("Web configuration review (nikto/whatweb) was skipped.")
    if any(h.os_matches == [] for h in hosts):
        notes.append("Operating system detection was not enabled (needs root and is unreliable over filtered links).")
    return notes


def analyse(
    hosts: Sequence[Host],
    *,
    tls_results: Sequence | None = None,
    fingerprints: Sequence | None = None,
    nikto_items: Sequence | None = None,
    tls_covered: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    findings += nse_findings(hosts, tls_covered=tls_covered)
    findings += exposure_findings(hosts)
    findings += version_findings(hosts)
    if fingerprints or nikto_items:
        findings += web_findings(fingerprints or [], nikto_items or [])
    if tls_results:
        findings += tls_findings(tls_results)
    return dedupe(findings)
