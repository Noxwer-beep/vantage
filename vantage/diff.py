"""Comparing two scans.

The point of a diff is to answer "did anything change since last week?" without
re-reading two reports. Findings carry a stable `key`, so identity survives a
re-run; ports are compared as sets per host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}


@dataclass
class ScanDiff:
    base_id: str
    compare_id: str
    base_target: str = ""
    compare_target: str = ""
    base_started: str = ""
    compare_started: str = ""
    base_score: int = 0
    compare_score: int = 0
    new: list[dict[str, Any]] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)
    persisting: list[dict[str, Any]] = field(default_factory=list)
    changed: list[dict[str, Any]] = field(default_factory=list)
    new_ports: list[dict[str, Any]] = field(default_factory=list)
    closed_ports: list[dict[str, Any]] = field(default_factory=list)
    base_hosts: int = 0
    compare_hosts: int = 0
    same_target: bool = True

    @property
    def score_delta(self) -> int:
        return self.compare_score - self.base_score

    @property
    def noisy(self) -> bool:
        return bool(self.new or self.resolved or self.new_ports or self.closed_ports)

    def counts_new(self) -> dict[str, int]:
        return _count_by_severity(self.new)

    def counts_resolved(self) -> dict[str, int]:
        return _count_by_severity(self.resolved)


def _count_by_severity(items: list[dict]) -> dict[str, int]:
    counts = {s: 0 for s in SEV_ORDER}
    for f in items:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _port_set(scan: dict) -> set[tuple[str, int]]:
    ports: set[tuple[str, int]] = set()
    for host in scan.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") == "open":
                ports.add((host.get("address", ""), int(port.get("number", 0))))
    return ports


def _score(scan: dict) -> int:
    summary = scan.get("summary") or {}
    return int(summary.get("score") or 0)


def diff_scans(base: dict, compare: dict) -> ScanDiff:
    """Diff two `ScanResult.to_dict()` payloads: base → compare."""
    out = ScanDiff(
        base_id=base.get("scan_id", ""),
        compare_id=compare.get("scan_id", ""),
        base_target=base.get("target", ""),
        compare_target=compare.get("target", ""),
        base_started=base.get("started", ""),
        compare_started=compare.get("started", ""),
        base_score=_score(base),
        compare_score=_score(compare),
        base_hosts=len(base.get("hosts", [])),
        compare_hosts=len(compare.get("hosts", [])),
        same_target=base.get("target") == compare.get("target"),
    )

    base_findings = {f.get("key"): f for f in base.get("findings", []) if f.get("key")}
    compare_findings = {f.get("key"): f for f in compare.get("findings", []) if f.get("key")}

    for key, finding in compare_findings.items():
        if key not in base_findings:
            out.new.append(finding)
            continue
        old = base_findings[key]
        out.persisting.append(finding)
        if old.get("severity") != finding.get("severity") or old.get("confidence") != finding.get("confidence"):
            out.changed.append(
                {
                    "key": key,
                    "title": finding.get("title", ""),
                    "location": finding.get("location", ""),
                    "severity_before": old.get("severity"),
                    "severity_after": finding.get("severity"),
                    "confidence_before": old.get("confidence"),
                    "confidence_after": finding.get("confidence"),
                }
            )

    out.resolved = [f for k, f in base_findings.items() if k not in compare_findings]

    def sort_key(f: dict) -> tuple:
        return (SEV_RANK.get(f.get("severity"), 9), f.get("location", ""))

    out.new.sort(key=sort_key)
    out.resolved.sort(key=sort_key)
    out.persisting.sort(key=sort_key)

    base_ports = _port_set(base)
    compare_ports = _port_set(compare)
    out.new_ports = [
        {"host": h, "port": p} for h, p in sorted(compare_ports - base_ports)
    ]
    out.closed_ports = [
        {"host": h, "port": p} for h, p in sorted(base_ports - compare_ports)
    ]
    return out


# ---------------------------------------------------------------- markdown

def render_markdown(d) -> str:
    lines: list[str] = []
    add = lines.append

    add(f"# Scan diff — {d.compare_target or d.compare_id}")
    add("")
    add(f"**Base:** `{d.base_id}` · {d.base_started} · score {d.base_score}")
    add(f"**Compare:** `{d.compare_id}` · {d.compare_started} · score {d.compare_score}")
    add("")
    delta = d.score_delta
    arrow = "▲" if delta > 0 else ("▼" if delta < 0 else "=")
    add(f"**Risk change:** {arrow} {delta:+d} (from {d.base_score} to {d.compare_score})")
    if not d.same_target:
        add("")
        add("> Warning: the two scans have different targets. The comparison is only "
            "meaningful for the same scope.")
    add("")

    add("## Summary")
    add("")
    add(f"- New findings: {len(d.new)}")
    add(f"- Resolved findings: {len(d.resolved)}")
    add(f"- Still present: {len(d.persisting)}")
    add(f"- Severity or confidence changed: {len(d.changed)}")
    add(f"- Newly open ports: {len(d.new_ports)}")
    add(f"- Closed ports: {len(d.closed_ports)}")
    add("")

    def section(title: str, items: list[dict]) -> None:
        if not items:
            return
        add(f"## {title}")
        add("")
        add("| Severity | Confidence | Location | Finding |")
        add("|---|---|---|---|")
        for f in items:
            add(
                f"| {f.get('severity', '')} | {f.get('confidence', '')} | "
                f"`{f.get('location', '')}` | {f.get('title', '')} |"
            )
        add("")

    section("New findings", d.new)
    section("Resolved findings", d.resolved)

    if d.changed:
        add("## Changed")
        add("")
        add("| Location | Finding | Before | After |")
        add("|---|---|---|---|")
        for c in d.changed:
            add(
                f"| `{c['location']}` | {c['title']} | "
                f"{c['severity_before']}/{c['confidence_before']} | "
                f"{c['severity_after']}/{c['confidence_after']} |"
            )
        add("")

    if d.new_ports or d.closed_ports:
        add("## Port changes")
        add("")
        if d.new_ports:
            add("Newly open: " + ", ".join(f"`{p['host']}:{p['port']}`" for p in d.new_ports))
        if d.closed_ports:
            add("Closed: " + ", ".join(f"`{p['host']}:{p['port']}`" for p in d.closed_ports))
        add("")

    if not (d.new or d.resolved or d.changed or d.new_ports or d.closed_ports):
        add("No changes. The two scans agree on every finding and open port.")
        add("")

    return "\n".join(lines)


def to_dict(d: ScanDiff) -> dict[str, Any]:
    return {
        "base_id": d.base_id,
        "compare_id": d.compare_id,
        "base_target": d.base_target,
        "compare_target": d.compare_target,
        "base_started": d.base_started,
        "compare_started": d.compare_started,
        "base_score": d.base_score,
        "compare_score": d.compare_score,
        "score_delta": d.score_delta,
        "same_target": d.same_target,
        "counts": {
            "new": len(d.new),
            "resolved": len(d.resolved),
            "persisting": len(d.persisting),
            "changed": len(d.changed),
            "new_ports": len(d.new_ports),
            "closed_ports": len(d.closed_ports),
        },
        "new": d.new,
        "resolved": d.resolved,
        "changed": d.changed,
        "new_ports": d.new_ports,
        "closed_ports": d.closed_ports,
    }
