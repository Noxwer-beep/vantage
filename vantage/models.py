"""Result model: hosts, ports, and findings.

The model deliberately separates three things that tools often blur together:

  * what was *observed*  (Host/Port — facts from the wire)
  * what it *means*      (Finding — an interpretation, with a confidence)
  * how bad it *would be* if true (severity)

A finding carries a `confidence`, because "banner says OpenSSH 5.3" is not the
same claim as "NSE proved this host is exploitable".
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any

from .config import CONFIDENCE_SCALE, SEVERITY_FLOOR, SEVERITY_RANK, SEVERITY_WEIGHT


@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    reason: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        parts = [self.service or "unknown"]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts)

    @property
    def banner(self) -> str:
        bits = [self.product, self.version, self.extrainfo]
        return " ".join(b for b in bits if b).strip()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # `banner` is a derived property, and the report templates read it from the
        # dict — without this every row in "product / version" renders as a dash.
        data["banner"] = self.banner
        return data


@dataclass
class Host:
    address: str
    hostname: str = ""
    state: str = "up"
    ports: list[Port] = field(default_factory=list)
    os_matches: list[dict[str, Any]] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)
    source: str = "nmap"

    @property
    def display(self) -> str:
        return f"{self.hostname} ({self.address})" if self.hostname else self.address

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]

    def port(self, number: int, protocol: str = "tcp") -> Port | None:
        for p in self.ports:
            if p.number == number and p.protocol == protocol:
                return p
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "hostname": self.hostname,
            "state": self.state,
            "os_matches": self.os_matches,
            "scripts": self.scripts,
            "ports": [p.to_dict() for p in self.ports],
            "source": self.source,
        }


@dataclass
class Finding:
    """One interpreted observation, with provenance and a fix."""

    title: str
    severity: str = "info"
    category: str = "general"
    host: str = ""
    port: int | None = None
    protocol: str = "tcp"
    service: str = ""
    evidence: str = ""
    detail: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    confidence: str = "informational"
    cvss: float | None = None
    source: str = ""
    cves: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            self.severity = "info"
        if self.confidence not in CONFIDENCE_SCALE:
            self.confidence = "informational"

    # -- identity ---------------------------------------------------------

    @property
    def key(self) -> str:
        """Stable identity so re-runs collapse instead of duplicating."""
        blob = "|".join(
            str(x)
            for x in (
                self.host,
                self.port or "",
                self.category,
                self.title.lower().strip(),
            )
        )
        return hashlib.sha1(blob.encode()).hexdigest()[:12]

    @property
    def sort_key(self) -> tuple:
        return (
            SEVERITY_RANK.get(self.severity, 9),
            -CONFIDENCE_SCALE.get(self.confidence, 0),
            self.host,
            self.port or 0,
            self.title,
        )

    @property
    def weighted(self) -> float:
        base = SEVERITY_WEIGHT.get(self.severity, 0)
        return base * CONFIDENCE_SCALE.get(self.confidence, 0)

    @property
    def location(self) -> str:
        if self.port:
            return f"{self.host}:{self.port}/{self.protocol}"
        return self.host

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["key"] = self.key
        data["location"] = self.location
        data["weighted"] = round(self.weighted, 2)
        return data


def risk_score(findings: list[Finding]) -> int:
    """0-100, saturating, with a severity floor.

    Two forces combine:

      * *volume*: enough medium findings add up (log curve, so it saturates
        instead of running away);
      * *a floor per finding*: one confirmed critical must never score lower
        than a pile of low findings, because those are not the same risk.

    The result is a triage number, not a CVSS score. It exists so a report can
    be sorted at a glance.
    """
    if not findings:
        return 0
    total = sum(f.weighted for f in findings)
    volume = 100 * (1 - 2.718281828 ** (-total / 60))
    floor = max(
        SEVERITY_FLOOR.get(f.severity, 0) * CONFIDENCE_SCALE.get(f.confidence, 0)
        for f in findings
    )
    return int(min(100, round(max(volume, floor))))


def grade(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "clean"


def summarise(findings: list[Finding]) -> dict[str, Any]:
    counts = {s: 0 for s in SEVERITY_RANK}
    confirmed = 0
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        if f.confidence == "confirmed":
            confirmed += 1
    score = risk_score(findings)
    return {
        "total": len(findings),
        "counts": counts,
        "confirmed": confirmed,
        "score": score,
        "grade": grade(score),
    }
