import json
import logging
import os
from datetime import datetime
from threading import Lock, Thread
from typing import List

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for

from tasmota_scanner import DEFAULT_PORTS, ScanError, expand_ip_range, scan_range
from version import APP_VERSION

DEFAULT_SCAN_RANGE = os.getenv("TASMOTA_FLEET_RANGE", "192.168.1.0/24")
SCAN_CACHE_FILE = os.getenv("SCAN_CACHE_FILE", "scan_results.json")

# In-memory cache for the last scan result
scan_state = {
    "range": DEFAULT_SCAN_RANGE,
    "devices": [],
    "stats": {},
    "status": "idle",  # idle, running, done, error
    "progress": {"done": 0, "total": 0, "last_ip": None},
    "last_error": None,
}
state_lock = Lock()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("tasmotafleet")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-tasmota-fleet")
    app.config["DEFAULT_SCAN_RANGE"] = DEFAULT_SCAN_RANGE
    app.config["SCAN_MAX_HOSTS"] = int(os.getenv("SCAN_MAX_HOSTS", "512"))
    app.config["SCAN_CACHE_FILE"] = SCAN_CACHE_FILE

    # load cached results (if any) at startup
    startup_notice = _load_cached_results(app.config["SCAN_CACHE_FILE"])
    if startup_notice:
        app.config["STARTUP_NOTICE"] = startup_notice

    @app.context_processor
    def inject_globals():
        return {
            "app_version": APP_VERSION,
            "nav_scan_form_id": "scanForm",
        }

    @app.route("/")
    def index():
        notice = app.config.pop("STARTUP_NOTICE", None)
        if notice:
            flash(notice, "warning")
        return render_template(
            "index.html",
            scan_state=scan_state,
            default_range=app.config["DEFAULT_SCAN_RANGE"],
        )

    @app.route("/scan", methods=["POST"])
    def trigger_scan():
        ip_range = request.form.get("ip_range", app.config["DEFAULT_SCAN_RANGE"]).strip()
        selected_ports = _parse_ports(request.form.getlist("ports"))
        ports = selected_ports or list(DEFAULT_PORTS)

        with state_lock:
            if scan_state["status"] == "running":
                flash("Ein Scan läuft bereits. Bitte warte einen Moment.", "warning")
                return redirect(url_for("index"))

        try:
            targets = expand_ip_range(ip_range, max_hosts=app.config["SCAN_MAX_HOSTS"])
        except ScanError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("index"))

        with state_lock:
            scan_state.update(
                {
                    "range": ip_range,
                    "devices": [],
                    "status": "running",
                    "progress": {"done": 0, "total": len(targets), "last_ip": None},
                    "last_error": None,
                    "stats": {
                        "duration": None,
                        "started_at": datetime.now(),
                        "hosts_total": len(targets),
                        "ports": ports,
                    },
                }
            )

        logger.info("Starte Scan: Range=%s, Hosts=%d, Ports=%s", ip_range, len(targets), ports)
        Thread(
            target=_run_scan,
            args=(ip_range, ports, app.config["SCAN_MAX_HOSTS"], app.config["SCAN_CACHE_FILE"]),
            daemon=True,
        ).start()

        flash("Scan gestartet … Fortschritt wird angezeigt.", "info")
        return redirect(url_for("index"))

    @app.route("/scan/status")
    def scan_status():
        with state_lock:
            stats = scan_state.get("stats", {}).copy()
            started_at = stats.get("started_at")
            if isinstance(started_at, datetime):
                stats["started_at"] = started_at.isoformat()
            payload = {
                "status": scan_state.get("status"),
                "progress": scan_state.get("progress", {}),
                "stats": stats,
                "devices_found": len(scan_state.get("devices", [])),
                "devices": list(scan_state.get("devices", [])),
                "range": scan_state.get("range"),
                "last_error": scan_state.get("last_error"),
            }
        return jsonify(payload)

    return app


def _parse_ports(raw_ports: List[str]) -> List[int]:
    ports: List[int] = []
    for value in raw_ports:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if port > 0:
            ports.append(port)
    return ports


def _run_scan(ip_range: str, ports: List[int], max_hosts: int, cache_path: str) -> None:
    def _progress(done: int, total: int, ip: str) -> None:
        with state_lock:
            scan_state["progress"] = {"done": done, "total": total, "last_ip": ip}
        # log jeden Host, um Fortschritt transparent zu halten
        logger.info("Scan Fortschritt %s: %d/%d (Host %s)", ip_range, done, total, ip)

    try:
        result = scan_range(
            ip_range,
            ports=ports,
            max_hosts=max_hosts,
            progress_cb=_progress,
        )
    except Exception as exc:  # broad by intention: we want to capture any scan failure
        logger.exception("Scan fehlgeschlagen: %s", ip_range)
        with state_lock:
            scan_state["status"] = "error"
            scan_state["last_error"] = str(exc)
        return

    with state_lock:
        scan_state["devices"] = result["devices"]
        scan_state["stats"] = {
            "duration": result["duration"],
            "started_at": result["started_at"],
            "hosts_total": result["hosts_total"],
            "ports": result["ports"],
        }
        scan_state["status"] = "done"
        scan_state["progress"] = {
            "done": result["hosts_total"],
            "total": result["hosts_total"],
            "last_ip": None,
        }
        scan_state["last_error"] = None

    logger.info(
        "Scan abgeschlossen: Range=%s, Geräte=%d, Dauer=%.2fs",
        ip_range,
        len(result["devices"]),
        result["duration"],
    )
    _persist_scan_results(cache_path)


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=5000, debug=True)


def _persist_scan_results(path: str) -> None:
    try:
        payload = _export_state_for_persist()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        logger.info("Scan-Ergebnisse gespeichert: %s", path)
    except Exception:
        logger.exception("Konnte Scan-Ergebnisse nicht speichern: %s", path)


def _export_state_for_persist() -> dict:
    with state_lock:
        payload = {
            "range": scan_state.get("range"),
            "devices": scan_state.get("devices", []),
            "stats": scan_state.get("stats", {}),
            "status": scan_state.get("status"),
            "progress": scan_state.get("progress", {}),
            "last_error": scan_state.get("last_error"),
        }

    stats = payload.get("stats") or {}
    if isinstance(stats.get("started_at"), datetime):
        stats = stats.copy()
        stats["started_at"] = stats["started_at"].isoformat()
    payload["stats"] = stats
    return payload


def _load_cached_results(path: str) -> str | None:
    if not os.path.exists(path):
        return "Keine gespeicherten Scan-Ergebnisse gefunden. Bitte Scan starten."

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        logger.exception("Konnte gespeicherte Scan-Ergebnisse nicht laden.")
        return "Gespeicherte Scan-Ergebnisse konnten nicht geladen werden. Bitte erneut scannen."

    stats = data.get("stats", {}) or {}
    started_at = stats.get("started_at")
    if isinstance(started_at, str):
        try:
            stats["started_at"] = datetime.fromisoformat(started_at)
        except ValueError:
            stats["started_at"] = None

    with state_lock:
        scan_state.update(
            {
                "range": data.get("range") or DEFAULT_SCAN_RANGE,
                "devices": data.get("devices", []),
                "stats": stats,
                "status": data.get("status", "idle"),
                "progress": data.get("progress", {"done": 0, "total": 0, "last_ip": None}),
                "last_error": data.get("last_error"),
            }
        )

    logger.info("Gespeicherte Scan-Ergebnisse geladen: %s", path)
    return None
