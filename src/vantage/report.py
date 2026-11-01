"""Report rendering: JSON, Markdown and a self-contained HTML document.

The HTML report embeds its own CSS and contains no external references, so it
can be handed to a client or archived without breaking.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__, config
from .models import summarise

TEMPLATES = Path(__file__).parent / "templates"

SEVERITY_COLORS = {
    "critical": "#ff4d5a",
    "high": "#ff8f3f",
    "medium": "#f5c451",
    "low": "#5aa9ff",
    "info": "#8b95a3",
}

_SAFE_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(enabled_extensions=("html", "xml", "j2")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["sev_color"] = lambda s: SEVERITY_COLORS.get(s, SEVERITY_COLORS["info"])
    env.filters["human_duration"] = _human_duration
    return env


def _human_duration(seconds: float | int | None) -> str:
    try:
        total = float(seconds or 0)
    except (TypeError, ValueError):
        return "—"
    if total < 60:
        return f"{total:.0f}s"
    minutes, secs = divmod(int(total), 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def _shape(data: dict[str, Any]) -> dict[str, Any]:
    """Normalise a ScanResult payload for templates."""
    findings = data.get("findings", [])
    summary = data.get("summary") or summarise([])
    grouped: dict[str, list[dict]] = {s: [] for s in config.SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        grouped.setdefault(sev if sev in _SAFE_SEVERITIES else "info", []).append(f)

    hosts = []
    for host in data.get("hosts", []):
        ports = sorted(
            [p for p in host.get("ports", []) if p.get("state") == "open"],
            key=lambda p: p.get("number", 0),
        )
        hosts.append({**host, "open_ports": ports})

    scope = (data.get("guard") or {}).get("scope", {}) or {}
    guard = data.get("guard") or {}
    return {
        **data,
        "findings_grouped": grouped,
        "summary": summary,
        "hosts_open": hosts,
        "scope": scope,
        "guard": guard,
        "generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "tool_version": __version__,
        "severity_order": config.SEVERITY_ORDER,
        "severity_colors": SEVERITY_COLORS,
        "counts": summary.get("counts", {}),
    }


def render_markdown(data: dict[str, Any]) -> str:
    return _env().get_template("report.md.j2").render(**_shape(data))


def render_html(data: dict[str, Any]) -> str:
    return _env().get_template("report.html.j2").render(**_shape(data))


def render_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def write_reports(data: dict[str, Any], outdir: str | Path | None = None) -> dict[str, str]:
    """Write all three formats and return the paths."""
    scan_id = data.get("scan_id", "scan")
    target_dir = Path(outdir).expanduser() if outdir else config.ensure_dirs()["reports"]
    scan_dir = target_dir / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "html": scan_dir / "report.html",
        "md": scan_dir / "report.md",
        "json": scan_dir / "report.json",
    }
    paths["html"].write_text(render_html(data), encoding="utf-8")
    paths["md"].write_text(render_markdown(data), encoding="utf-8")
    paths["json"].write_text(render_json(data), encoding="utf-8")
    return {k: str(v) for k, v in paths.items()}
