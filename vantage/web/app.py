"""Local web interface.

Bound to 127.0.0.1 by default: this is an operator console, not a service.
Scans run in a background thread and the page polls a JSON status endpoint, so
progress is live without websockets or a JS build step.
"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from .. import __version__, config, diff as diffmod, report as reporting, scope as scoping, store
from ..config import SEVERITY_ORDER
from ..engine import Engine, PHASE_LABELS
from ..models import summarise

SCAN_ID_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{4}$")

JOBS: dict[str, dict[str, Any]] = {}
LOCK = threading.Lock()


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    config.ensure_dirs()

    @app.context_processor
    def inject_globals() -> dict:
        return {
            "version": __version__,
            "severity_order": SEVERITY_ORDER,
            "now": time.strftime("%Y-%m-%d %H:%M"),
        }

    # ------------------------------------------------------------ views

    @app.get("/")
    def index():
        scans = store.list_scans(limit=12)
        stats = store.stats()
        return render_template("index.html", scans=scans, stats=stats, profiles=config.PROFILES)

    @app.post("/scan")
    def start_scan():
        target = (request.form.get("target") or "").strip()
        profile = request.form.get("profile") or "standard"
        scope_text = (request.form.get("scope") or "").strip()
        authorized = request.form.get("authorized") == "on"
        allow_public = request.form.get("allow_public") == "on"

        if not authorized:
            return render_template(
                "error.html",
                title="Authorisation required",
                message="The authorisation checkbox must be ticked. Vantage will not scan "
                        "a system you cannot show permission for.",
            ), 400
        if profile not in config.PROFILES:
            profile = "standard"

        scope = None
        if scope_text:
            tokens = scoping.parse_targets_blob(scope_text.replace("\n", " "))
            try:
                scope = scoping.Scope.from_targets(tokens, name="web-form")
            except scoping.ScopeError as exc:
                return render_template("error.html", title="Invalid scope", message=str(exc)), 400
        try:
            guard = scoping.authorize(
                target,
                scope=scope,
                statement="I HAVE PERMISSION",
                allow_public=allow_public,
            )
        except scoping.ScopeError as exc:
            store_record_refusal(target, str(exc))
            return render_template("error.html", title="Refused", message=str(exc)), 400

        engine = Engine(guard, profile)
        scan_id = engine.result.scan_id
        state: dict[str, Any] = {
            "scan_id": scan_id,
            "target": guard.target,
            "profile": profile,
            "status": "running",
            "progress": 0,
            "phase": "starting",
            "logs": [],
            "findings": [],
            "warnings": list(guard.warnings),
            "errors": [],
            "started": engine.result.started,
            "finished": "",
            "summary": {},
            "hosts": 0,
            "open_ports": 0,
            "assets": [],
            "phases": [],
            "host_addrs": [],
        }
        engine.emit = _make_emit(state)
        with LOCK:
            JOBS[scan_id] = state
            # keep the registry bounded
            if len(JOBS) > 40:
                for old in sorted(JOBS)[: len(JOBS) - 40]:
                    if JOBS[old]["status"] != "running":
                        JOBS.pop(old, None)

        thread = threading.Thread(
            target=_run_job, args=(engine, state), name=f"scan-{scan_id}", daemon=True
        )
        thread.start()
        return redirect(url_for("scan_detail", scan_id=scan_id))

    @app.get("/scan/<scan_id>")
    def scan_detail(scan_id: str):
        _validate_id(scan_id)
        state = _state_for(scan_id)
        if state is None:
            abort(404)
        return render_template("scan.html", state=state)

    @app.get("/history")
    def history():
        scans = store.list_scans(limit=200)
        stats = store.stats()
        return render_template("history.html", scans=scans, stats=stats)

    @app.get("/diff/<base>/<compare>")
    def diff_view(base: str, compare: str):
        _validate_id(base)
        _validate_id(compare)
        base_scan = store.get_scan(base)
        compare_scan = store.get_scan(compare)
        if base_scan is None or compare_scan is None:
            abort(404)
        d = diffmod.diff_scans(base_scan, compare_scan)
        return render_template("diff.html", d=d, data=diffmod.to_dict(d))

    @app.get("/api/diff/<base>/<compare>")
    def api_diff(base: str, compare: str):
        _validate_id(base)
        _validate_id(compare)
        base_scan = store.get_scan(base)
        compare_scan = store.get_scan(compare)
        if base_scan is None or compare_scan is None:
            return jsonify({"error": "unknown scan"}), 404
        return jsonify(diffmod.to_dict(diffmod.diff_scans(base_scan, compare_scan)))

    @app.get("/help")
    def help_page():
        return render_template("help.html")

    # ------------------------------------------------------------ api

    @app.get("/api/scan/<scan_id>")
    def api_scan(scan_id: str):
        _validate_id(scan_id)
        state = _state_for(scan_id)
        if state is None:
            return jsonify({"error": "unknown scan"}), 404
        with LOCK:
            payload = {
                **state,
                "logs": state["logs"][-60:],
                "findings": state["findings"][:200],
                "assets": state["assets"][-40:],
                "asset_total": len(state["assets"]),
                "phase_label": PHASE_LABELS.get(state["phase"], state["phase"]),
            }
        return jsonify(payload)

    @app.get("/api/scans")
    def api_scans():
        return jsonify(store.list_scans(limit=50))

    @app.get("/scan/<scan_id>/report")
    def report_view(scan_id: str):
        _validate_id(scan_id)
        data = store.get_scan(scan_id)
        if data is None:
            abort(404)
        return reporting.render_html(data)

    @app.get("/scan/<scan_id>/download/<fmt>")
    def report_download(scan_id: str, fmt: str):
        _validate_id(scan_id)
        data = store.get_scan(scan_id)
        if data is None:
            abort(404)
        if fmt == "json":
            body, mime, ext = reporting.render_json(data), "application/json", "json"
        elif fmt == "md":
            body, mime, ext = reporting.render_markdown(data), "text/markdown", "md"
        elif fmt == "html":
            body, mime, ext = reporting.render_html(data), "text/html", "html"
        else:
            abort(400)
        path = config.ensure_dirs()["reports"] / f"{scan_id}.{ext}"
        path.write_text(body, encoding="utf-8")
        return send_file(path, mimetype=mime, as_attachment=True, download_name=f"vantage-{scan_id}.{ext}")

    # ------------------------------------------------------------ errors

    @app.errorhandler(404)
    def not_found(_exc):
        return render_template("error.html", title="Not found",
                               message="That page or scan does not exist."), 404

    @app.errorhandler(500)
    def server_error(exc):  # pragma: no cover
        return render_template("error.html", title="Server error", message=str(exc)), 500

    return app


# ---------------------------------------------------------------- jobs

def _make_emit(state: dict[str, Any]):
    """Build the engine -> job-state bridge for one scan."""

    def emit(event: str, payload: dict) -> None:
        with LOCK:
            if event == "phase":
                state["phase"] = payload["key"]
                state["progress"] = int(
                    100 * (payload["index"] - 1) / max(payload["total"], 1)
                )
                state["phases"] = [
                    p for p in state["phases"] if p.get("key") != payload["key"]
                ]
                state["phases"].append(
                    {
                        "key": payload["key"],
                        "label": payload.get("label", payload["key"]),
                        "index": payload.get("index", 0),
                        "total": payload.get("total", 1),
                        "status": "running",
                        "note": "",
                        "duration_s": None,
                    }
                )
            elif event == "phase_done":
                state["progress"] = payload.get("progress", state["progress"])
                for entry in state["phases"]:
                    if entry["key"] == payload["key"]:
                        entry["status"] = payload.get("status", "done")
                        entry["note"] = payload.get("note", "")
                        entry["duration_s"] = payload.get("duration_s")
                        break
            elif event == "log":
                state["logs"].append(payload["message"])
                if len(state["logs"]) > 500:
                    del state["logs"][: len(state["logs"]) - 500]
            elif event == "asset":
                state["assets"].append(payload)
                state["hosts"] = len({a["host"] for a in state["assets"]})
                state["open_ports"] = len(state["assets"])
            elif event == "host":
                if payload["host"] not in state["host_addrs"]:
                    state["host_addrs"].append(payload["host"])
                state["hosts"] = max(state["hosts"], len(state["host_addrs"]))
            elif event == "warning":
                if payload["message"] not in state["warnings"]:
                    state["warnings"].append(payload["message"])
            elif event == "finding":
                state["findings"].append(payload)

    return emit


def _run_job(engine: Engine, state: dict[str, Any]) -> None:
    try:
        result = engine.run()
        data = result.to_dict()
        with LOCK:
            state.update(
                {
                    "status": data["status"],
                    "progress": 100,
                    "finished": data["finished"],
                    "summary": data["summary"],
                    "findings": data["findings"],
                    "logs": data["logs"],
                    "warnings": data["warnings"],
                    "errors": data["errors"],
                    "hosts": len(data["hosts"]),
                    "open_ports": sum(
                        len([p for p in h["ports"] if p["state"] == "open"])
                        for h in data["hosts"]
                    ),
                    "assets": data.get("assets", []),
                    "phases": data.get("phases", []),
                }
            )
        try:
            store.save_scan(result)
            reporting.write_reports(data)
        except Exception as exc:  # noqa: BLE001
            with LOCK:
                state["errors"].append(f"report write failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        with LOCK:
            state["status"] = "failed"
            state["errors"].append(f"{type(exc).__name__}: {exc}")
            state["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")


def _state_for(scan_id: str) -> dict[str, Any] | None:
    with LOCK:
        if scan_id in JOBS:
            return JOBS[scan_id]
    data = store.get_scan(scan_id)
    if data is None:
        return None
    return {
        "scan_id": scan_id,
        "target": data.get("target", ""),
        "profile": data.get("profile", ""),
        "status": data.get("status", "complete"),
        "progress": 100,
        "phase": "analyse",
        "logs": data.get("logs", []),
        "findings": data.get("findings", []),
        "warnings": data.get("warnings", []),
        "errors": data.get("errors", []),
        "started": data.get("started", ""),
        "finished": data.get("finished", ""),
        "summary": data.get("summary", {}),
        "hosts": len(data.get("hosts", [])),
        "open_ports": sum(
            len([p for p in h.get("ports", []) if p.get("state") == "open"])
            for h in data.get("hosts", [])
        ),
        "assets": data.get("assets", []),
        "phases": data.get("phases", []),
        "host_addrs": [h.get("address") for h in data.get("hosts", [])],
    }


def _validate_id(scan_id: str) -> None:
    if not SCAN_ID_RE.match(scan_id or ""):
        abort(404)


def store_record_refusal(target: str, reason: str) -> None:
    scoping.audit({"event": "refused", "reason": "web-form", "target": target,
                   "detail": reason[:300]})


def serve(host: str = "127.0.0.1", port: int = 8765, debug: bool = False) -> None:
    app = create_app()
    store.init_db()
    app.run(host=host, port=port, debug=debug, use_reloader=False, threaded=True)
