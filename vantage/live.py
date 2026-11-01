"""Live terminal dashboard for a running scan.

A `rich.live` frame that updates in place: phase timeline, live asset count,
findings as they land, and the last tool message. It is fed by the engine's
event stream and never talks to the engine's internals.

Rendering is deliberately cheap — a fixed number of short lines, rebuilt from a
small state dict on every tick — so it stays smooth while nmap is working.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.table import Table
from rich.text import Text

from .config import PHASE_LABELS

SEV_STYLE = {
    "critical": "bold #ff4d5a",
    "high": "#ff8f3f",
    "medium": "#f5c451",
    "low": "#5aa9ff",
    "info": "dim",
}

STATUS_MARK = {
    "running": ("▸", "bold #57e0c9"),
    "done": ("✓", "green"),
    "skipped": ("–", "dim"),
    "failed": ("✗", "red"),
    "pending": ("·", "dim"),
}

MAX_ASSETS = 4000


class LiveView:
    """Terminal dashboard driven by engine events."""

    def __init__(self, console: Console, target: str, strategy, phases: list[str]) -> None:
        self.console = console
        self.target = target
        self.strategy = strategy
        self._planned = list(phases)
        self._lock = threading.Lock()
        self._live: Live | None = None
        self._started = time.monotonic()

        self._phases: dict[str, dict[str, Any]] = {}
        self._order: list[str] = []
        # Show the whole plan from the start, so the shape of the run is visible
        # before anything has happened.
        for key in self._planned:
            self._order.append(key)
            self._phases[key] = {
                "label": PHASE_LABELS.get(key, key),
                "status": "pending",
                "note": "",
                "started": None,
                "duration_s": None,
            }
        self._assets: dict[tuple[str, int], dict] = {}
        self._hosts: set[str] = set()
        self._findings: deque = deque(maxlen=3)
        self._counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self._total_findings = 0
        self._last_log = ""
        self._warning = ""
        self._percent = 0
        self._finished = False

    # -- lifecycle --------------------------------------------------------

    def __enter__(self) -> "LiveView":
        self._live = Live(
            self.render(),
            console=self.console,
            refresh_per_second=8,
            transient=False,
            vertical_overflow="visible",
            get_renderable=self.render,
        )
        self._live.__enter__()
        return self

    def __exit__(self, *exc_info) -> None:
        if self._live is not None:
            self._live.__exit__(*exc_info)
            self._live = None
        return None

    # -- events -----------------------------------------------------------

    def on_event(self, event: str, payload: dict) -> None:
        with self._lock:
            if event == "phase":
                key = payload["key"]
                entry = self._phases.get(key)
                if entry is None:                    # phase outside the plan
                    self._order.append(key)
                    entry = {"label": payload.get("label", key), "note": "", "duration_s": None}
                    self._phases[key] = entry
                entry["label"] = payload.get("label", entry["label"])
                entry["status"] = "running"
                entry["started"] = time.monotonic()
                self._percent = int(100 * (payload.get("index", 1) - 1) / max(payload.get("total", 1), 1))
            elif event == "phase_done":
                entry = self._phases.get(payload["key"])
                if entry:
                    entry["status"] = payload.get("status", "done")
                    entry["note"] = payload.get("note", "")
                    entry["duration_s"] = payload.get("duration_s")
                self._percent = payload.get("progress", self._percent)
            elif event == "asset":
                key = (payload["host"], payload["port"])
                if key not in self._assets and len(self._assets) < MAX_ASSETS:
                    self._assets[key] = payload
                self._hosts.add(payload["host"])
            elif event == "host":
                self._hosts.add(payload["host"])
            elif event == "finding":
                self._total_findings += 1
                sev = payload.get("severity", "info")
                self._counts[sev] = self._counts.get(sev, 0) + 1
                self._findings.append(payload)
            elif event == "log":
                self._last_log = payload.get("message", "")
            elif event == "warning":
                self._warning = payload.get("message", "")
            elif event == "done":
                self._finished = True
                self._percent = 100

    # -- render -----------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "percent": self._percent,
                "hosts": len(self._hosts),
                "ports": len(self._assets),
                "findings": dict(self._counts),
                "total_findings": self._total_findings,
                "phases": [
                    {"key": k, **{kk: vv for kk, vv in self._phases[k].items() if kk != "started"}}
                    for k in self._order
                ],
                "finished": self._finished,
            }

    def render(self) -> RenderableType:
        with self._lock:
            elapsed = time.monotonic() - self._started
            percent = self._percent
            hosts = len(self._hosts)
            ports = len(self._assets)
            counts = dict(self._counts)
            total_findings = self._total_findings
            findings = list(self._findings)
            last_log = self._last_log
            warning = self._warning
            phases = [(k, dict(v)) for k, v in self._phases.items()]
            order = list(self._order)

        width = max(40, self.console.width - 2)
        rows: list[RenderableType] = []

        # header
        head = Text()
        head.append("VANTAGE", style="bold")
        head.append("  ·  ", style="dim")
        head.append(self.target, style="bold cyan")
        head.append(f"  ·  {self.strategy.name}", style="dim")
        head.append(f"   {_clock(elapsed)}", style="dim")
        rows.append(head)

        # progress bar
        bar_width = max(10, width - 8)
        filled = int(bar_width * percent / 100)
        bar = Text()
        bar.append("━" * filled, style="#57e0c9")
        bar.append("━" * (bar_width - filled), style="#2a343c")
        bar.append(f" {percent:3d}%", style="dim")
        rows.append(bar)

        # phase timeline
        label_w = max(16, min(36, width - 34))
        note_w = max(12, width - label_w - 6)
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(width=2, no_wrap=True)
        table.add_column(width=label_w, no_wrap=True, overflow="ellipsis")
        table.add_column(justify="right", width=note_w, no_wrap=True, overflow="ellipsis")
        for key in order:
            entry = self._phases.get(key, {})
            mark, style = STATUS_MARK.get(entry.get("status", "pending"), ("·", "dim"))
            running = entry.get("status") == "running"
            label = Text(entry.get("label", key), style="bold" if running else "")
            detail = entry.get("note") or ""
            if running:
                detail = "running…"
            elif entry.get("status") == "pending":
                detail = ""
            dur = entry.get("duration_s")
            if dur is not None:
                detail = f"{detail}  {dur:g}s" if detail else f"{dur:g}s"
            table.add_row(Text(mark, style=style), label, Text(detail, style="dim"))
        rows.append(table)

        # counters
        counters = Text()
        counters.append(f"{hosts} host(s)", style="bold")
        counters.append("  ·  ", style="dim")
        counters.append(f"{ports} open port(s)", style="bold")
        counters.append("  ·  ", style="dim")
        if total_findings:
            for sev, n in counts.items():
                if n:
                    counters.append(f"{n}{sev[0].upper()} ", style=SEV_STYLE[sev])
        else:
            counters.append("no findings yet", style="dim")
        rows.append(counters)

        # live findings
        if findings and self.console.height > 18:
            for f in findings[-3:]:
                line = Text()
                sev = f.get("severity", "info")
                line.append(f" {sev[:4].upper():<5}", style=SEV_STYLE.get(sev, "dim"))
                line.append(f"{f.get('location', '')[:24]:<26}", style="dim")
                line.append(f.get("title", "")[: max(10, width - 34)], style="")
                rows.append(line)

        if warning:
            rows.append(Text(f" ! {warning[: width - 4]}", style="yellow"))
        elif last_log:
            rows.append(Text(f"  {last_log[: width - 2]}", style="dim"))

        return Group(*rows)


def _clock(seconds: float) -> str:
    total = int(seconds)
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"
