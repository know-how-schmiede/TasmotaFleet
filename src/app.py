import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock, Thread
from typing import Dict, List

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for

from .tasmota_scanner import (
    DEFAULT_PORTS,
    ScanError,
    expand_ip_range,
    fetch_device_status,
    scan_range,
)
from .version import APP_VERSION

DEFAULT_SCAN_RANGE = os.getenv("TASMOTA_FLEET_RANGE", "192.168.1.0/24")
BASE_DIR = Path(__file__).resolve().parent
# keep scan results and settings in separate files within the package directory by default
SCAN_CACHE_FILE = os.getenv("SCAN_CACHE_FILE") or str(BASE_DIR / "scan_results.json")
SETTINGS_FILE = os.getenv("TASMOTA_FLEET_SETTINGS") or str(BASE_DIR / "TasmotaFleetSet.JSON")
DEFAULT_REFRESH_MS = 5000
DEFAULT_PROGRESS = {"done": 0, "total": 0, "last_ip": None}
PROGRESS_STALE_AFTER_SEC = 30

# In-memory cache for the last scan result
scan_state = {
    "range": DEFAULT_SCAN_RANGE,
    "devices": [],
    "stats": {},
    "status": "idle",  # idle, running, done, error
    "progress": DEFAULT_PROGRESS.copy(),
    "last_error": None,
}
state_lock = Lock()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("tasmotafleet")


def _enable_scanner_debug_logging_from_env() -> None:
    """
    Optional verbose logs for tasmota_scanner, controlled via env var TASMOTA_SCANNER_DEBUG.
    """
    flag = os.getenv("TASMOTA_SCANNER_DEBUG", "")
    if str(flag).lower() not in ("1", "true", "yes", "debug"):
        return

    scanner_logger = logging.getLogger("src.tasmota_scanner")
    scanner_logger.setLevel(logging.DEBUG)
    if not scanner_logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        scanner_logger.addHandler(handler)
    scanner_logger.propagate = False
    logger.info("Scanner Debug-Logging aktiviert (TASMOTA_SCANNER_DEBUG=%s)", flag)


_enable_scanner_debug_logging_from_env()


def _empty_progress(*, total: int = 0) -> dict:
    """
    Generate a fresh progress dict to avoid reusing shared mutable defaults.
    """
    return {"done": 0, "total": total, "last_ip": None}


def _progress_for_status(status: str | None, progress: dict | None, stats: dict | None = None) -> dict:
    """
    Return progress for an active or freshly finished scan.
    Progress from older runs is discarded so the UI starts empty after a reload.
    """
    if status == "running" and progress:
        return {
            "done": int(progress.get("done") or 0),
            "total": int(progress.get("total") or 0),
            "last_ip": progress.get("last_ip"),
        }

    if status == "done" and progress and stats:
        finished_at = stats.get("started_at")
        duration = stats.get("duration")
        if isinstance(finished_at, datetime) and isinstance(duration, (int, float)):
            finished_at = finished_at + timedelta(seconds=float(duration))
            age = (datetime.now() - finished_at).total_seconds()
            if age <= PROGRESS_STALE_AFTER_SEC:
                return {
                    "done": int(progress.get("done") or 0),
                    "total": int(progress.get("total") or 0),
                    "last_ip": progress.get("last_ip"),
                }

    return _empty_progress()


def _scan_state_for_view() -> dict:
    """
    Create a snapshot of the scan_state that is safe for rendering
    (e.g., strips stale progress values).
    """
    with state_lock:
        snapshot = dict(scan_state)
        snapshot["progress"] = _progress_for_status(
            snapshot.get("status"),
            snapshot.get("progress"),
            snapshot.get("stats"),
        )
    return snapshot


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-tasmota-fleet")
    app.config["DEFAULT_SCAN_RANGE"] = DEFAULT_SCAN_RANGE
    app.config["SCAN_MAX_HOSTS"] = int(os.getenv("SCAN_MAX_HOSTS", "512"))
    app.config["SCAN_CACHE_FILE"] = SCAN_CACHE_FILE
    app.config["REFRESH_INTERVAL_MS"] = int(os.getenv("REFRESH_INTERVAL_MS", str(DEFAULT_REFRESH_MS)))
    app.config["SETTINGS_FILE"] = SETTINGS_FILE

    # load settings from file (overrides defaults)
    settings_notice = _load_settings(app)

    # load cached results (if any) at startup
    startup_notice = _load_cached_results(app.config["SCAN_CACHE_FILE"])
    if startup_notice:
        app.config["STARTUP_NOTICE"] = startup_notice
    if settings_notice:
        app.config["SETTINGS_NOTICE"] = settings_notice

    @app.context_processor
    def inject_globals():
        return {
            "app_version": APP_VERSION,
        }

    @app.route("/")
    def index():
        notice = app.config.pop("STARTUP_NOTICE", None)
        settings_notice = app.config.pop("SETTINGS_NOTICE", None)
        if notice:
            flash(notice, "warning")
        if settings_notice:
            flash(settings_notice, "warning")
        return render_template(
            "index.html",
            scan_state=_scan_state_for_view(),
            default_range=app.config["DEFAULT_SCAN_RANGE"],
            refresh_interval_ms=app.config["REFRESH_INTERVAL_MS"],
        )

    @app.route("/scan", methods=["GET", "POST"])
    def scan_page():
        if request.method == "POST":
            ip_range = request.form.get("ip_range", app.config["DEFAULT_SCAN_RANGE"]).strip()
            selected_ports = _parse_ports(request.form.getlist("ports"))
            ports = selected_ports or list(DEFAULT_PORTS)

            with state_lock:
                if scan_state["status"] == "running":
                    flash("Ein Scan laeuft bereits. Bitte warte einen Moment.", "warning")
                    return redirect(url_for("scan_page"))

            try:
                targets = expand_ip_range(ip_range, max_hosts=app.config["SCAN_MAX_HOSTS"])
            except ScanError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("scan_page"))

            with state_lock:
                scan_state.update(
                    {
                        "range": ip_range,
                        "devices": [],
                        "status": "running",
                        "progress": _empty_progress(total=len(targets)),
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

            flash("Scan gestartet - Fortschritt wird angezeigt.", "info")
            return redirect(url_for("scan_page"))

        return render_template(
            "scan.html",
            scan_state=_scan_state_for_view(),
            default_range=app.config["DEFAULT_SCAN_RANGE"],
            refresh_interval_ms=app.config["REFRESH_INTERVAL_MS"],
        )

    @app.route("/scan/status")
    def scan_status():
        payload = _build_status_payload(include_devices=True)
        return jsonify(payload)

    @app.route("/settings", methods=["GET", "POST"])
    def settings_page():
        if request.method == "POST":
            new_range = request.form.get("default_range", app.config["DEFAULT_SCAN_RANGE"]).strip()
            new_max_hosts_raw = request.form.get("scan_max_hosts", str(app.config["SCAN_MAX_HOSTS"])).strip()
            new_cache_file = request.form.get("scan_cache_file", app.config["SCAN_CACHE_FILE"]).strip()
            new_refresh_raw = request.form.get("refresh_interval_ms", str(app.config["REFRESH_INTERVAL_MS"])).strip()

            # validate range
            try:
                expand_ip_range(new_range, max_hosts=1024)
            except ScanError as exc:
                flash(f"IP-Range ungültig: {exc}", "danger")
                return redirect(url_for("settings_page"))

            # validate max hosts
            try:
                new_refresh_ms = int(new_refresh_raw)
                if new_refresh_ms < 500:
                    raise ValueError
            except ValueError:
                flash("Refresh-Time muss mindestens 500 ms betragen.", "danger")
                return redirect(url_for("settings_page"))

            # adjust max_hosts to at least cover current range size to avoid hard errors
            try:
                current_hosts = len(expand_ip_range(new_range, max_hosts=10_000))
            except ScanError:
                current_hosts = 0
            new_max_hosts = max(current_hosts, _coerce_positive_int(new_max_hosts_raw, app.config["SCAN_MAX_HOSTS"]))

            with state_lock:
                app.config["DEFAULT_SCAN_RANGE"] = new_range
                app.config["SCAN_MAX_HOSTS"] = new_max_hosts
                app.config["SCAN_CACHE_FILE"] = new_cache_file or SCAN_CACHE_FILE
                app.config["REFRESH_INTERVAL_MS"] = new_refresh_ms
                # update scan_state default range for UI convenience
                if scan_state.get("status") == "idle":
                    scan_state["range"] = new_range

            _save_settings(app)

            flash("Einstellungen gespeichert.", "success")
            return redirect(url_for("settings_page"))

        return render_template(
            "settings.html",
            default_range=app.config["DEFAULT_SCAN_RANGE"],
            scan_max_hosts=app.config["SCAN_MAX_HOSTS"],
            scan_cache_file=app.config["SCAN_CACHE_FILE"],
            refresh_interval_ms=app.config["REFRESH_INTERVAL_MS"],
        )

    @app.route("/devices/refresh")
    def devices_refresh():
        # take snapshot to avoid holding lock during network I/O
        with state_lock:
            current_devices = [dict(d) for d in scan_state.get("devices", [])]

        refreshed: List[Dict] = []
        for dev in current_devices:
            info = fetch_device_status(dev.get("ip"), int(dev.get("port", 80)), request_timeout=1.2)
            if info:
                dev.update(
                    {
                        "power": info.get("power", dev.get("power")),
                        "rssi": info.get("rssi", dev.get("rssi")),
                        "version": info.get("version", dev.get("version")),
                        "hostname": info.get("hostname", dev.get("hostname")),
                        "friendly_name": info.get("friendly_name", dev.get("friendly_name")),
                        "device_name": info.get("device_name", dev.get("device_name")),
                        "name": info.get("name", dev.get("name")),
                    }
                )
            refreshed.append(dev)

        with state_lock:
            scan_state["devices"] = refreshed

        payload = {
            "devices": refreshed,
            "count": len(refreshed),
            "stats": _serialize_stats(scan_state.get("stats", {})),
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
        logger.info("Scan Fortschritt %s: %d/%d (Host %s)", ip_range, done, total, ip)

    try:
        result = scan_range(
            ip_range,
            ports=ports,
            max_hosts=max_hosts,
            progress_cb=_progress,
        )
    except Exception as exc:  # broad by intention: capture any scan failure
        logger.exception("Scan fehlgeschlagen: %s", ip_range)
        with state_lock:
            scan_state["status"] = "error"
            scan_state["last_error"] = str(exc)
        return

    logger.info("Gefundene Devices (%d):", len(result["devices"]))
    for dev in result["devices"]:
        name = (
            dev.get("device_name")
            or dev.get("name")
            or dev.get("friendly_name")
            or dev.get("hostname")
            or "Tasmota Geraet"
        )
        logger.info("  %s @ %s:%s", name, dev.get("ip"), dev.get("port"))

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
        "Scan abgeschlossen: Range=%s, Geraete=%d, Dauer=%.2fs",
        ip_range,
        len(result["devices"]),
        result["duration"],
    )
    _persist_scan_results(cache_path)


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080, debug=True)


def _persist_scan_results(path: str) -> None:
    try:
        payload = _export_state_for_persist()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        logger.exception("Konnte Scan-Ergebnisse nicht speichern: %s", path)
    else:
        logger.info("Scan-Ergebnisse gespeichert: %s", path)


def _export_state_for_persist() -> dict:
    with state_lock:
        status = scan_state.get("status")
        stats = scan_state.get("stats", {})
        payload = {
            "range": scan_state.get("range"),
            "devices": scan_state.get("devices", []),
            "stats": stats,
            "status": status,
            "progress": _progress_for_status(status, scan_state.get("progress"), stats),
            "last_error": scan_state.get("last_error"),
        }

    stats = payload.get("stats") or {}
    if isinstance(stats.get("started_at"), datetime):
        stats = stats.copy()
        stats["started_at"] = stats["started_at"].isoformat()
    payload["stats"] = stats
    return payload


def _coerce_positive_int(value: str, fallback: int, minimum: int = 1) -> int:
    try:
        iv = int(value)
        if iv < minimum:
            return fallback
        return iv
    except Exception:
        return fallback


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

    status = data.get("status", "idle")
    if status == "running":
        # A running scan cannot survive an app restart; treat it as idle instead.
        status = "idle"
    progress = _progress_for_status(status, data.get("progress"), stats)

    with state_lock:
        scan_state.update(
            {
                "range": data.get("range") or DEFAULT_SCAN_RANGE,
                "devices": data.get("devices", []),
                "stats": stats,
                "status": status,
                "progress": progress,
                "last_error": data.get("last_error"),
            }
        )

    logger.info("Gespeicherte Scan-Ergebnisse geladen: %s", path)
    return None


def _serialize_stats(stats: dict) -> dict:
    stats_copy = stats.copy()
    started_at = stats_copy.get("started_at")
    if isinstance(started_at, datetime):
        stats_copy["started_at"] = started_at.isoformat()
    return stats_copy


def _build_status_payload(include_devices: bool = False) -> dict:
    with state_lock:
        status = scan_state.get("status") or "idle"
        stats_raw = scan_state.get("stats", {})
        stats = _serialize_stats(stats_raw)
        payload = {
            "status": status,
            "progress": _progress_for_status(status, scan_state.get("progress"), stats_raw),
            "stats": stats,
            "devices_found": len(scan_state.get("devices", [])),
            "range": scan_state.get("range"),
            "last_error": scan_state.get("last_error"),
        }
        if include_devices:
            payload["devices"] = list(scan_state.get("devices", []))
    return payload


def _load_settings(app: Flask) -> str | None:
    path = app.config["SETTINGS_FILE"]
    if not os.path.exists(path):
        return "Keine Settings-Datei gefunden. Es werden Standardwerte verwendet."

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        logger.exception("Konnte Settings nicht laden.")
        return "Settings-Datei konnte nicht geladen werden. Es werden Standardwerte verwendet."

    new_range = data.get("default_range") or app.config["DEFAULT_SCAN_RANGE"]
    new_max_hosts = _coerce_positive_int(str(data.get("scan_max_hosts", "")), app.config["SCAN_MAX_HOSTS"], 1)
    new_cache = data.get("scan_cache_file") or app.config["SCAN_CACHE_FILE"]
    new_refresh = _coerce_positive_int(str(data.get("refresh_interval_ms", "")), app.config["REFRESH_INTERVAL_MS"], 500)

    with state_lock:
        app.config["DEFAULT_SCAN_RANGE"] = new_range
        app.config["SCAN_MAX_HOSTS"] = new_max_hosts
        app.config["SCAN_CACHE_FILE"] = new_cache
        app.config["REFRESH_INTERVAL_MS"] = new_refresh
        if scan_state.get("status") == "idle":
            scan_state["range"] = new_range

    logger.info("Settings geladen: %s", path)
    return None


def _save_settings(app: Flask) -> None:
    path = app.config["SETTINGS_FILE"]
    payload = {
        "default_range": app.config["DEFAULT_SCAN_RANGE"],
        "scan_max_hosts": app.config["SCAN_MAX_HOSTS"],
        "scan_cache_file": app.config["SCAN_CACHE_FILE"],
        "refresh_interval_ms": app.config["REFRESH_INTERVAL_MS"],
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        logger.info("Settings gespeichert: %s", path)
    except Exception:
        logger.exception("Konnte Settings nicht speichern: %s", path)
