"""Command-line interface.

    vantage scan 192.168.1.0/24 --scope homelab --authorized
    vantage ui
    vantage history
    vantage report 20260101-120000-a1b2

Exit codes: 0 ok · 1 error · 2 refused (authorisation/scope) · 3 missing tool
            · 4 findings at or above --fail-on
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import webbrowser
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

from . import __version__, config, diff as diffmod, report as reporting, scope as scoping, store
from .config import SEVERITY_ORDER, SEVERITY_RANK
from .engine import Engine, PHASE_LABELS
from .live import LiveView
from .models import summarise

console = Console()
err_console = Console(stderr=True)

SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

BANNER = r"""
 __     __             _        _
 \ \   / /_ _ _ __  _(_)__ _| |_ ___
  \ \ / / _` | '_ \| |/ _` | __/ _ \
   \ V / (_| | | | | | (_| | ||  __/
    \_/ \__,_|_| |_|_|\__,_|\__\___|"""


def sev_badge(sev: str) -> Text:
    return Text(sev.upper().ljust(8), style=SEV_STYLE.get(sev, "dim"))


def header(subtitle: str = "") -> None:
    t = Text()
    t.append("VANTAGE", style="bold")
    t.append("  ·  authorized recon & vulnerability triage", style="dim")
    if subtitle:
        t.append(f"\n{subtitle}", style="dim italic")
    console.print(Panel(t, border_style="bright_black", padding=(0, 2), expand=False))
    console.print()


# ---------------------------------------------------------------- rendering

def render_summary(data: dict) -> None:
    summary = data.get("summary") or summarise([])
    score, grade = summary.get("score", 0), summary.get("grade", "clean")
    style = SEV_STYLE.get(grade, "dim")

    grid = Table.grid(padding=(0, 3))
    grid.add_column(justify="right")
    grid.add_column()
    grid.add_row("risk", Text(f"{score}/100", style=f"bold {style}"))
    grid.add_row("grade", Text(grade, style=style))
    counts = summary.get("counts", {})
    parts = []
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if n:
            parts.append(f"[{SEV_STYLE.get(sev, 'dim')}]{n} {sev}[/]")
    grid.add_row("findings", Text.from_markup("  ".join(parts) if parts else "none"))
    grid.add_row("confirmed", Text(str(summary.get("confirmed", 0))))
    grid.add_row("hosts", Text(f"{len(data.get('hosts', []))} up · "
                               f"{sum(len([p for p in h['ports'] if p['state'] == 'open']) for h in data.get('hosts', []))} open ports"))
    grid.add_row("duration", Text(reporting._human_duration(data.get("duration_s"))))
    console.print(Panel(grid, title="[bold]result[/]", border_style="bright_black", expand=False))


def render_findings(findings: list[dict], limit: int = 20) -> None:
    if not findings:
        console.print()
        console.print("  [dim]No findings. That means nothing was detected — not that the target is secure.[/]")
        console.print()
        return
    table = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, expand=True)
    table.add_column("SEV", width=9, no_wrap=True)
    table.add_column("LOCATION", style="cyan", no_wrap=True, width=21)
    table.add_column("CONF", width=10, no_wrap=True)
    table.add_column("FINDING", overflow="ellipsis", no_wrap=True, ratio=1)

    for f in findings[:limit]:
        table.add_row(
            sev_badge(f.get("severity", "info")),
            f.get("location", ""),
            Text(f.get("confidence", ""), style="dim"),
            f.get("title", ""),
        )
    console.print(table)
    if len(findings) > limit:
        console.print(f"  [dim]… {len(findings) - limit} more · vantage show <id> --full[/]")
    console.print()


# ---------------------------------------------------------------- commands

def cmd_scan(args: argparse.Namespace) -> int:
    # --json promises machine-readable output, so nothing else may touch stdout.
    json_mode = bool(args.json)
    say = (lambda *_a, **_k: None) if json_mode else console.print
    if not json_mode:
        header()

    scope = None
    if args.scope:
        try:
            scope = scoping.check_scope_file(args.scope)
        except scoping.ScopeError as exc:
            err_console.print(f"[red]scope error:[/] {exc}")
            return 2
        say(f"  scope    [bold]{scope.name}[/] · {scope.summary()} · ~{scope.host_count()} address(es)")
    else:
        say("  scope    [yellow]none supplied[/] — implicit authorisation for this target only")

    statement = "I HAVE PERMISSION" if args.authorized else None
    if statement is None:
        if not sys.stdin.isatty():
            err_console.print(
                "[red]refusing to scan:[/] no authorisation statement. "
                "Pass --authorized (only if you own the target or hold written permission)."
            )
            return 2
        console.print()
        console.print(Panel(
            "Vantage only runs against systems you own or have [bold]written permission[/] to test.\n"
            "Scanning without authorisation is a criminal offence in most jurisdictions\n"
            "(§202a-c StGB in Germany, CFAA in the US, Computer Misuse Act in the UK).\n\n"
            f"Target: [bold]{args.target}[/]",
            title="[yellow]authorisation required[/]",
            border_style="yellow",
            expand=False,
        ))
        if not Confirm.ask("Do you own this target or hold written permission to test it?", default=False):
            err_console.print("[red]aborted — nothing was scanned[/]")
            return 2
        statement = "I HAVE PERMISSION"

    try:
        guard = scoping.authorize(
            args.target,
            scope=scope,
            statement=statement,
            allow_public=args.allow_public,
            allow_large=args.allow_large,
            max_hosts=args.max_hosts,
        )
    except scoping.AuthorizationRequired as exc:
        err_console.print(f"[red]refused:[/] {exc}")
        return 2
    except scoping.ScopeError as exc:
        err_console.print(f"[red]refused:[/] {exc}")
        return 2

    for w in guard.warnings:
        say(f"  [yellow]![/] {w}")
    say(f"  target   [bold]{guard.target}[/] · {', '.join(guard.networks)}")
    say(f"  operator [dim]{guard.operator}[/] · authorised · fingerprint [dim]{guard.scope.fingerprint()}[/]")

    profile = config.get_profile(args.profile)
    # --strategy overrides: apply them to the phase list, which is the source
    # of truth, instead of toggling booleans that no longer exist as fields.
    if args.no_vuln:
        profile = config.without_phases(profile, "vuln")
    if args.no_web:
        profile = config.without_phases(profile, "web")
    if args.no_tls:
        profile = config.without_phases(profile, "tls")
    if args.no_services:
        profile = config.without_phases(profile, "services")
    if args.only:
        profile = config.with_phases(profile, *[p.strip() for p in args.only.split(",") if p.strip()])
    if args.timing:
        profile = config.with_timing(profile, args.timing)
    if args.ports:
        profile = config.with_ports(profile, args.ports)
        if "ports" not in profile.phases:
            profile = config.with_phases(profile, "ports")

    say(f"  strategy [bold]{profile.name}[/] · {profile.title}")
    say(f"  phases   {profile.description}")
    say(f"  estimate [dim]{profile.estimate()}[/]")
    say()

    limits = config.Limits(max_hosts=args.max_hosts, timeout=dict(config.SCAN_TIMEOUTS))
    state = {"phase": "", "done": 0, "total": 0}

    def emit(event: str, payload: dict) -> None:
        if event == "phase":
            state["phase"] = payload["label"]
            state["total"] = payload["total"]
            state["done"] = payload["index"] - 1
            say(
                f"[bold cyan]▸ {payload['index']}/{payload['total']}[/] [bold]{payload['label']}[/]"
            )
        elif event == "phase_done":
            note = payload.get("note") or ""
            status = payload.get("status")
            mark = "✓" if status == "done" else ("–" if status == "skipped" else "✗")
            style = "green" if status == "done" else ("dim" if status == "skipped" else "red")
            say(f"  [{style}]{mark}[/] [dim]{note}[/]" if note else f"  [{style}]{mark}[/]")
        elif event == "log":
            if not args.quiet and (args.verbose or args.dry_run):
                say(f"    [dim]{payload['message']}[/]", highlight=False)
        elif event == "warning":
            say(f"  [yellow]! {payload['message']}[/]")

    engine = Engine(guard, profile, limits=limits, emit=emit, dry_run=args.dry_run)

    # A live dashboard needs a real terminal and a human watching it; --json,
    # --plain and piped output fall back to line-by-line reporting.
    live_ok = (
        not json_mode
        and not args.plain
        and not args.quiet
        and console.is_terminal
        and not args.dry_run
    )
    view: LiveView | None = None
    if live_ok:
        view = LiveView(console, guard.target, profile, engine.plan())
        engine.emit = view.on_event

    try:
        if view is not None:
            with view:
                result = engine.run()
        else:
            result = engine.run()
    except KeyboardInterrupt:
        err_console.print("\n[yellow]interrupted[/] — no report written")
        return 1

    data = result.to_dict()

    if json_mode:
        json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return _exit_for(data, args.fail_on)

    console.print()
    render_summary(data)
    render_findings(data["findings"], limit=args.show)

    if result.warnings:
        console.print("[yellow]notices[/]")
        for w in result.warnings:
            console.print(f"  · {w}", style="dim")
        console.print()
    if result.errors:
        console.print("[red]errors[/]")
        for e in result.errors:
            console.print(f"  · {e}")
        console.print()

    saved_paths: dict[str, str] = {}
    if not args.no_save and data.get("status") != "dry-run":
        try:
            store.save_scan(result)
            saved_paths = reporting.write_reports(data, args.output)
        except Exception as exc:  # noqa: BLE001
            err_console.print(f"[red]could not write report:[/] {exc}")
    elif args.output and data.get("status") != "dry-run":
        saved_paths = reporting.write_reports(data, args.output)

    if saved_paths:
        console.print("[bold]reports[/]")
        for fmt in ("html", "md", "json"):
            if fmt in saved_paths:
                console.print(f"  {fmt:<5} [cyan]{saved_paths[fmt]}[/]")
        if args.open_report:
            webbrowser.open(f"file://{saved_paths['html']}")
        console.print()
    console.print(f"[dim]scan id[/] [bold]{data['scan_id']}[/]")

    return _exit_for(data, args.fail_on)


def _exit_for(data: dict, fail_on: str) -> int:
    if data.get("status") == "failed":
        return 1
    if fail_on in (None, "none"):
        return 0
    threshold = SEVERITY_RANK.get(fail_on, 99)
    for f in data.get("findings", []):
        if SEVERITY_RANK.get(f.get("severity"), 99) <= threshold:
            return 4
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    from .web.app import serve

    header("starting the local web interface")
    url = f"http://{args.host}:{args.port}"
    console.print(f"  [bold]{url}[/]  [dim](bound to {args.host} only — use --host to change)[/]")
    console.print("  [dim]Ctrl-C to stop[/]\n")
    if args.open:
        webbrowser.open(url)
    try:
        serve(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        console.print("\n[dim]stopped[/]")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    header()
    scans = store.list_scans(limit=args.limit)
    if not scans:
        console.print("  [dim]No scans recorded yet. Run `vantage scan <target> --authorized`.[/]")
        return 0
    table = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, expand=True)
    table.add_column("SCAN ID", style="cyan", no_wrap=True, width=17)
    table.add_column("TARGET", no_wrap=True, overflow="ellipsis", ratio=1)
    table.add_column("RISK", width=4, justify="right", no_wrap=True)
    table.add_column("SEVERITY", width=20, no_wrap=True)
    table.add_column("STATUS", width=9, no_wrap=True)
    letters = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I"}
    for s in scans:
        counts = s.get("counts") or {}
        parts = " ".join(
            f"[{SEV_STYLE.get(k, 'dim')}]{counts.get(k, 0)}{letters[k]}[/]"
            for k in SEVERITY_ORDER
            if counts.get(k)
        ) or "[dim]clean[/]"
        grade = s.get("grade") or "clean"
        table.add_row(
            s["id"],
            s["target"],
            Text(str(s.get("score") or 0), style=SEV_STYLE.get(grade, "dim")),
            Text.from_markup(parts),
            s.get("status", ""),
        )
    console.print(table)
    console.print()
    console.print(
        "  [dim]vantage show <id>   ·   C=critical H=high M=medium L=low I=info[/]"
    )
    console.print()
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    data = store.get_scan(args.scan_id)
    if data is None:
        err_console.print(f"[red]no scan with id {args.scan_id}[/]")
        return 1
    header(f"scan {data['scan_id']} · {data['target']}")
    render_summary(data)
    render_findings(data.get("findings", []), limit=args.show)
    if args.full:
        for f in data.get("findings", []):
            console.rule(f"[bold]{f['title']}[/]")
            console.print(f"[dim]{f['location']}[/]")
            console.print(Panel(f.get("evidence", ""), title="evidence", border_style="bright_black"))
            console.print(f"[bold]detail[/] {f.get('detail','')}\n")
            console.print(f"[bold green]remediation[/] {f.get('remediation','')}\n")
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    rows = store.query_findings(
        severity=args.severity, host=args.host, limit=args.limit, scan_id=args.scan
    )
    if not rows:
        console.print("[dim]no matching findings[/]")
        return 0
    table = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, expand=True)
    table.add_column("SCAN", width=17, no_wrap=True)
    table.add_column("SEV", width=8, no_wrap=True)
    table.add_column("HOST", no_wrap=True, overflow="ellipsis", ratio=1)
    table.add_column("PORT", width=5, no_wrap=True, justify="right")
    table.add_column("FINDING", no_wrap=True, overflow="ellipsis", ratio=2)
    for r in rows:
        table.add_row(
            r["scan_id"], sev_badge(r["severity"]), r["host"],
            str(r["port"] or ""), r["title"],
        )
    console.print(table)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    data = store.get_scan(args.scan_id)
    if data is None:
        err_console.print(f"[red]no scan with id {args.scan_id}[/]")
        return 1
    if args.format == "json":
        console.print_json(json.dumps(data))
        return 0
    if args.format == "md":
        console.print(reporting.render_markdown(data))
        return 0
    outdir = Path(args.output) if args.output else None
    paths = reporting.write_reports(data, outdir)
    console.print(f"[green]wrote[/] {paths['html']}")
    console.print(f"[green]wrote[/] {paths['md']}")
    console.print(f"[green]wrote[/] {paths['json']}")
    if args.open:
        webbrowser.open(f"file://{paths['html']}")
    return 0


def cmd_scope(args: argparse.Namespace) -> int:
    if args.action == "check":
        try:
            scope = scoping.check_scope_file(args.path)
        except scoping.ScopeError as exc:
            err_console.print(f"[red]invalid scope:[/] {exc}")
            return 2
        console.print(f"[green]valid[/] scope [bold]{scope.name}[/] · "
                      f"{len(scope.networks)} network(s) · ~{scope.host_count()} addresses")
        for net in scope.networks:
            console.print(f"  · {net}")
        return 0
    if args.action == "new":
        try:
            targets: list[str] = []
            for raw in args.targets:
                targets.extend(scoping.parse_targets_blob(raw))
            if not targets:
                err_console.print("[red]no targets given[/] — use --targets 10.0.0.0/24 …")
                return 2
            scope = scoping.Scope.from_targets(
                targets, name=args.name or "scope", notes=args.notes or ""
            )
            scope.validate()
        except scoping.ScopeError as exc:
            err_console.print(f"[red]invalid scope:[/] {exc}")
            return 2
        path = Path(args.output or args.path)
        path.write_text(json.dumps(scope.to_dict(), indent=2) + "\n", encoding="utf-8")
        console.print(f"[green]wrote[/] {path}")
        for net in scope.networks:
            console.print(f"  · {net}")
        console.print(f"  [dim]~{scope.host_count()} address(es) · fingerprint {scope.fingerprint()}[/]")
        return 0
    err_console.print("usage: vantage scope {check,new}")
    return 1


def cmd_doctor(args: argparse.Namespace) -> int:
    header("environment check")
    import shutil

    import subprocess

    table = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, expand=False)
    table.add_column("TOOL", width=12)
    table.add_column("STATUS", width=10)
    table.add_column("DETAIL")
    checks = [
        ("nmap", True), ("nikto", False), ("whatweb", False), ("openssl", False),
    ]
    for name, required in checks:
        found = shutil.which(name)
        if found:
            table.add_row(name, "[green]ok[/]", found)
        else:
            table.add_row(
                name,
                "[red]missing[/]" if required else "[yellow]optional[/]",
                "install it to enable this phase" if not required else "nmap is required",
            )
    try:
        version = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
    except (OSError, subprocess.SubprocessError, IndexError):
        version = ""
    if version:
        table.add_row("nmap ver", "[dim]info[/]", version)
    table.add_row("privileges", "[green]root[/]" if _is_root() else "[yellow]user[/]",
                  "SYN scan + OS detection available" if _is_root() else "will use a TCP connect scan (-sT)")
    dirs = config.ensure_dirs()
    table.add_row("data dir", "[dim]info[/]", str(dirs["root"]))
    table.add_row("database", "[dim]info[/]", str(config.DB_PATH()))
    console.print(table)
    console.print()
    console.print("[dim]Vantage never passes --script-args unsafe=1, never attempts "
                  "credentials, and never writes outside its data directory.[/]")
    return 0


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def cmd_audit(args: argparse.Namespace) -> int:
    path = config.AUDIT_PATH()
    if not path.exists():
        console.print("[dim]no audit entries yet[/]")
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines[-args.tail:]:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = rec.get("event", "?")
        style = "green" if event == "authorized" else "red"
        console.print(
            f"[dim]{rec.get('ts','')}[/] [{style}]{event:<10}[/] "
            f"{rec.get('target','')} [dim]{rec.get('reason','') or rec.get('scope','')}[/]"
        )
    return 0


def cmd_strategies(args: argparse.Namespace) -> int:
    header("scan strategies")
    table = Table(box=None, show_header=False, pad_edge=False, expand=True)
    table.add_column(width=11, no_wrap=True)
    table.add_column(ratio=1)
    for s in config.list_strategies():
        name = Text(s.name, style="bold cyan")
        detail = Text()
        detail.append(s.title, style="bold")
        detail.append(f"  ·  {s.description}", style="dim")
        detail.append(f"\n{s.use_case}", style="")
        detail.append(f"\n{s.estimate()}", style="dim italic")
        table.add_row(name, detail)
    console.print(table)
    console.print(
        "  [dim]vantage scan <target> -p <strategy> --authorized\n"
        "  Narrow further with --only web,tls or --no-vuln / --no-web / --no-tls[/]"
    )
    console.print()
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    base = store.get_scan(args.base)
    compare = store.get_scan(args.compare)
    if base is None:
        err_console.print(f"[red]no scan with id {args.base}[/]")
        return 1
    if compare is None:
        err_console.print(f"[red]no scan with id {args.compare}[/]")
        return 1

    d = diffmod.diff_scans(base, compare)

    if args.json:
        json.dump(diffmod.to_dict(d), sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return _diff_exit(d, args.fail_on)

    header(f"diff  {d.base_id}  →  {d.compare_id}")

    if not d.same_target:
        console.print(
            f"  [yellow]![/] scans have different targets "
            f"({d.base_target} vs {d.compare_target}) — compare like with like"
        )

    delta = d.score_delta
    style = "red" if delta > 0 else ("green" if delta < 0 else "dim")
    arrow = "▲" if delta > 0 else ("▼" if delta < 0 else "=")
    console.print(
        f"  risk  {d.base_score} → {d.compare_score}  "
        f"[{style}]{arrow} {delta:+d}[/]   "
        f"[dim]{len(d.new)} new · {len(d.resolved)} resolved · "
        f"{len(d.persisting)} still present[/]"
    )
    console.print()

    if not d.noisy:
        console.print("  [green]No changes.[/] [dim]Both scans agree on every finding and open port.[/]")
        console.print()
    else:
        _diff_table("NEW", d.new, "red")
        _diff_table("RESOLVED", d.resolved, "green")

        if d.changed:
            table = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, expand=True)
            table.add_column("LOCATION", style="cyan", no_wrap=True, width=21)
            table.add_column("FINDING", no_wrap=True, overflow="ellipsis", ratio=1)
            table.add_column("BEFORE", width=16, no_wrap=True)
            table.add_column("AFTER", width=16, no_wrap=True)
            for c in d.changed:
                table.add_row(
                    c["location"],
                    c["title"],
                    f"{c['severity_before']}/{c['confidence_before']}",
                    f"{c['severity_after']}/{c['confidence_after']}",
                )
            console.print("[bold]CHANGED[/]  [dim]severity or confidence moved[/]")
            console.print(table)
            console.print()

        if d.new_ports:
            console.print("[bold]NEWLY OPEN PORTS[/]")
            console.print("  " + ", ".join(f"[cyan]{p['host']}:{p['port']}[/]" for p in d.new_ports))
            console.print()
        if d.closed_ports:
            console.print("[bold]CLOSED PORTS[/]")
            console.print("  " + ", ".join(f"[dim]{p['host']}:{p['port']}[/]" for p in d.closed_ports))
            console.print()

    if args.markdown:
        path = Path(args.markdown)
        path.write_text(diffmod.render_markdown(d), encoding="utf-8")
        console.print(f"[green]wrote[/] {path}")
        console.print()

    return _diff_exit(d, args.fail_on)


def _diff_table(title: str, items: list[dict], colour: str) -> None:
    if not items:
        return
    table = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, expand=True)
    table.add_column("SEV", width=9, no_wrap=True)
    table.add_column("LOCATION", style="cyan", no_wrap=True, width=21)
    table.add_column("CONF", width=10, no_wrap=True)
    table.add_column("FINDING", no_wrap=True, overflow="ellipsis", ratio=1)
    for f in items:
        table.add_row(
            sev_badge(f.get("severity", "info")),
            f.get("location", ""),
            Text(f.get("confidence", ""), style="dim"),
            f.get("title", ""),
        )
    console.print(f"[bold {colour}]{title}[/]  [dim]{len(items)}[/]")
    console.print(table)
    console.print()


def _diff_exit(d, fail_on: str) -> int:
    """Regression gate: fail when *new* findings reach the threshold."""
    if fail_on in (None, "none"):
        return 0
    threshold = SEVERITY_RANK.get(fail_on, 99)
    return 4 if any(SEVERITY_RANK.get(f.get("severity"), 99) <= threshold for f in d.new) else 0


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vantage",
        description="Authorized network reconnaissance and vulnerability triage.",
        epilog="Every scan needs an explicit authorisation statement. Use --authorized only "
               "for systems you own or have written permission to test.",
    )
    p.add_argument("--version", action="version", version=f"vantage {__version__}")
    sub = p.add_subparsers(dest="command", required=False)

    s = sub.add_parser("scan", help="scan a host or network")
    s.add_argument("target", help="IP, CIDR, or hostname")
    s.add_argument("-p", "--profile", "--strategy", dest="profile", default="standard",
                   choices=list(config.PROFILES), metavar="STRATEGY",
                   help="scan strategy (see `vantage strategies`)")
    s.add_argument("-s", "--scope", metavar="FILE", help="scope file (.json/.toml/.txt)")
    s.add_argument("--authorized", action="store_true",
                   help="confirm you own the target or hold written permission")
    s.add_argument("--allow-public", action="store_true",
                   help="permit public IP addresses (needs real authorisation)")
    s.add_argument("--allow-large", action="store_true",
                   help="permit ranges above the host ceiling")
    s.add_argument("--max-hosts", type=int, default=config.MAX_HOSTS_DEFAULT)
    s.add_argument("--ports", help="override the port specification passed to nmap")
    s.add_argument("--timing", type=int, choices=[0, 1, 2, 3, 4, 5],
                   help="nmap -T value (1-2 are gentle, 4-5 are loud)")
    s.add_argument("--no-vuln", action="store_true", help="skip NSE vuln scripts")
    s.add_argument("--no-web", action="store_true", help="skip nikto/whatweb")
    s.add_argument("--no-tls", action="store_true", help="skip TLS inspection")
    s.add_argument("--no-services", action="store_true", help="skip version detection")
    s.add_argument("-o", "--output", metavar="DIR", help="report output directory")
    s.add_argument("--json", action="store_true", help="print the result as JSON")
    s.add_argument("--show", type=int, default=20, help="findings to print (default 20)")
    s.add_argument("--no-save", action="store_true", help="do not store the scan or write reports")
    s.add_argument("--open-report", action="store_true", help="open the HTML report when done")
    s.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    s.add_argument("--plain", action="store_true",
                   help="line-by-line output instead of the live dashboard")
    s.add_argument("--only", metavar="PHASES",
                   help="force phases on, comma separated (e.g. web,tls)")
    s.add_argument("--fail-on", default="none",
                   choices=list(SEVERITY_ORDER) + ["none"],
                   help="exit 4 if a finding at this severity or worse exists (CI use)")
    s.add_argument("-q", "--quiet", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true", help="stream tool output")
    s.set_defaults(func=cmd_scan)

    u = sub.add_parser("ui", help="launch the local web interface")
    u.add_argument("--host", default="127.0.0.1")
    u.add_argument("--port", type=int, default=8765)
    u.add_argument("--open", action="store_true")
    u.add_argument("--debug", action="store_true")
    u.set_defaults(func=cmd_ui)

    h = sub.add_parser("history", help="list past scans")
    h.add_argument("-n", "--limit", type=int, default=25)
    h.set_defaults(func=cmd_history)

    sh = sub.add_parser("show", help="show one stored scan")
    sh.add_argument("scan_id")
    sh.add_argument("--show", type=int, default=20)
    sh.add_argument("--full", action="store_true", help="print evidence and remediation for every finding")
    sh.set_defaults(func=cmd_show)

    f = sub.add_parser("findings", help="query findings across scans")
    f.add_argument("--severity", choices=SEVERITY_ORDER)
    f.add_argument("--host")
    f.add_argument("--scan", dest="scan")
    f.add_argument("-n", "--limit", type=int, default=100)
    f.set_defaults(func=cmd_findings)

    r = sub.add_parser("report", help="re-render a stored scan")
    r.add_argument("scan_id")
    r.add_argument("--format", choices=["html", "md", "json"], default="html")
    r.add_argument("-o", "--output", metavar="DIR")
    r.add_argument("--open", action="store_true")
    r.set_defaults(func=cmd_report)

    sp = sub.add_parser("scope", help="work with scope files")
    sp.add_argument("action", choices=["check", "new"])
    sp.add_argument("path", nargs="?", default="scope.json")
    sp.add_argument("--targets", nargs="*", default=[], help="targets for `scope new`")
    sp.add_argument("--name")
    sp.add_argument("--notes")
    sp.add_argument("-o", "--output", default=None)
    sp.set_defaults(func=cmd_scope)

    d = sub.add_parser("doctor", help="check the toolchain")
    d.set_defaults(func=cmd_doctor)

    a = sub.add_parser("audit", help="show the authorisation audit log")
    a.add_argument("--tail", type=int, default=20)
    a.set_defaults(func=cmd_audit)

    st = sub.add_parser("strategies", help="list scan strategies and when to use them")
    st.set_defaults(func=cmd_strategies)

    df = sub.add_parser("diff", help="compare two stored scans")
    df.add_argument("base", help="the earlier scan id")
    df.add_argument("compare", help="the later scan id")
    df.add_argument("--json", action="store_true", help="machine-readable diff")
    df.add_argument("--markdown", metavar="PATH", help="also write a markdown diff")
    df.add_argument("--fail-on", default="none",
                    choices=list(SEVERITY_ORDER) + ["none"],
                    help="exit 4 if a NEW finding is at this severity or worse")
    df.set_defaults(func=cmd_diff)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        header()
        console.print("[dim]no command given — here is what it can do:[/]\n")
        parser.print_help()
        return 0
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 0
    return func(args)


if __name__ == "__main__":
    raise SystemExit(main())
