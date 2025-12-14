import datetime as dt
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Sequence
import logging

import requests
import urllib3

# suppress warnings for self-signed certs on local devices
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_PORTS: Sequence[int] = (80, 443)
logger = logging.getLogger(__name__)


class ScanError(ValueError):
    """Raised for invalid scan configuration (e.g., range too large)."""


def expand_ip_range(range_text: str, *, max_hosts: int = 512) -> List[str]:
    """
    Expand user input into a list of IPs.

    Supports:
    - CIDR:   192.168.0.0/24
    - range:  192.168.0.10-192.168.0.50
    - single: 192.168.0.10
    """
    if not range_text:
        raise ScanError("IP-Range fehlt.")

    text = range_text.strip()

    try:
        if "/" in text:
            network = ipaddress.ip_network(text, strict=False)
            hosts = list(network.hosts())
        elif "-" in text:
            start_text, end_text = text.split("-", 1)
            start = ipaddress.ip_address(start_text.strip())
            end = ipaddress.ip_address(end_text.strip())
            if int(end) < int(start):
                raise ScanError("Range-Ende liegt vor dem Range-Anfang.")
            hosts = [ipaddress.ip_address(i) for i in range(int(start), int(end) + 1)]
        else:
            hosts = [ipaddress.ip_address(text)]
    except ValueError as exc:
        raise ScanError(f"Ungueltiger IP-Range: {exc}") from exc

    if len(hosts) == 0:
        raise ScanError("Keine Hosts im Range.")

    if len(hosts) > max_hosts:
        raise ScanError(
            f"Zu viele Hosts ({len(hosts)}). Bitte Range verkleinern "
            f"oder max_hosts erhoehen."
        )

    return [str(host) for host in hosts]


def scan_range(
    range_text: str,
    *,
    ports: Sequence[int] = DEFAULT_PORTS,
    max_hosts: int = 512,
    connect_timeout: float = 0.6,
    request_timeout: float = 1.2,
    progress_cb: Optional[Callable[[int, int, str], None]] = None,
) -> Dict:
    """
    Scan an IP range for Tasmota devices listening on the given ports.

    Returns a dict containing:
    {
        "devices": [...],
        "hosts_total": int,
        "duration": float,
        "started_at": datetime,
        "ports": list[int],
    }
    """
    targets = expand_ip_range(range_text, max_hosts=max_hosts)
    start_ts = dt.datetime.now()
    started = time.perf_counter()

    devices: List[Dict] = []
    total_hosts = len(targets)
    done_count = 0

    with ThreadPoolExecutor(max_workers=min(32, len(targets))) as executor:
        futures = {
            executor.submit(
                _scan_single_host,
                ip,
                ports,
                connect_timeout,
                request_timeout,
            ): ip
            for ip in targets
        }

        for future in as_completed(futures):
            ip = futures[future]
            try:
                result = future.result()
            except Exception:
                # keep scanning if a single host misbehaves
                done_count += 1
                if progress_cb:
                    progress_cb(done_count, total_hosts, ip)
                continue
            if result:
                devices.extend(result)
            done_count += 1
            if progress_cb:
                progress_cb(done_count, total_hosts, ip)

    duration = time.perf_counter() - started
    return {
        "devices": sorted(devices, key=lambda x: (x["ip"], x["port"])),
        "hosts_total": len(targets),
        "duration": duration,
        "started_at": start_ts,
        "ports": list(ports),
    }


def _scan_single_host(
    ip: str,
    ports: Sequence[int],
    connect_timeout: float,
    request_timeout: float,
) -> List[Dict]:
    found: List[Dict] = []

    for port in ports:
        if not _is_port_open(ip, port, connect_timeout):
            continue

        device_info = _probe_tasmota(ip, port, request_timeout)
        if device_info:
            found.append(device_info)

    return found


def _is_port_open(ip: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            return True
        except (socket.timeout, OSError):
            return False


def _probe_tasmota(ip: str, port: int, request_timeout: float) -> Optional[Dict]:
    protocol = "https" if port == 443 else "http"
    base_url = f"{protocol}://{ip}"

    # First try JSON-based API endpoints
    parsed_payloads = []
    endpoint_hits = []
    endpoint_errors = []
    for endpoint in ("/cm?cmnd=Status%200", "/cm?cmnd=Status%208"):
        url = f"{base_url}{endpoint}"
        timeout = max(request_timeout, 2.5) if endpoint.startswith("/cm?cmnd=Status%200") else request_timeout
        try:
            resp = requests.get(url, timeout=timeout, verify=False)
        except requests.RequestException as exc:
            endpoint_errors.append((endpoint, f"request-failed: {exc}"))
            continue

        parsed = _parse_status_json(resp)
        if parsed:
            parsed_payloads.append(parsed)
            endpoint_hits.append((endpoint, resp.status_code))
        else:
            endpoint_errors.append(
                (
                    endpoint,
                    f"parse-failed status={resp.status_code} len={len(resp.content) if resp.content is not None else 'n/a'}",
                )
            )

    if parsed_payloads:
        merged = _merge_device_infos(parsed_payloads)
        merged.update(
            {
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "endpoint": ",".join([hit[0] for hit in endpoint_hits]),
                "http_status": endpoint_hits[0][1] if endpoint_hits else None,
                "url": base_url,
                "detected_via": "status-json",
            }
        )
        merged["name"] = (
            merged.get("device_name")
            or merged.get("friendly_name")
            or merged.get("hostname")
            or merged.get("name")
            or "Tasmota Geraet"
        )
        return merged

    if endpoint_errors:
        logger.debug("Kein Status-JSON fuer %s:%s -> %s", ip, port, endpoint_errors)

    # Fallback: check for Tasmota markers in the HTML landing page
    try:
        resp = requests.get(base_url, timeout=request_timeout, verify=False)
    except requests.RequestException:
        return None

    if resp.ok and "tasmota" in resp.text.lower():
        return {
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "endpoint": "/",
            "http_status": resp.status_code,
            "url": base_url,
            "detected_via": "html-probe",
            "name": "Tasmota (HTML)",
            "hostname": None,
            "friendly_name": None,
            "version": None,
            "mac": None,
            "rssi": None,
            "module": None,
            "power": None,
            "uptime": None,
        }

    return None


def fetch_device_status(ip: str, port: int, request_timeout: float = 1.2) -> Optional[Dict]:
    """
    Lightweight probe for a known device to refresh status (e.g., POWER, RSSI).
    Returns the same shape as _probe_tasmota (or None if unreachable).
    """
    return _probe_tasmota(ip, port, request_timeout)


def _parse_status_json(resp: requests.Response) -> Optional[Dict]:
    try:
        payload = resp.json()
    except ValueError:
        return None

    if not isinstance(payload, dict):
        return None

    status = payload.get("Status", {}) or {}
    status_prm = payload.get("StatusPRM", {}) or {}
    status_fwr = payload.get("StatusFWR", {}) or {}
    status_net = payload.get("StatusNET", {}) or {}
    status_sts = payload.get("StatusSTS", {}) or {}

    device_name = (
        status.get("DeviceName")
        or status_sts.get("DeviceName")
        or status_prm.get("DeviceName")
    )
    friendly_name = _pick_friendly_name(status, status_prm, status_sts)
    # Prefer the hostname reported by the device itself, not reverse DNS lookups
    hostname = (
        status_net.get("Hostname")
        or status_prm.get("Hostname")
        or status.get("Hostname")
        or status_sts.get("Hostname")
    )
    version = status_fwr.get("Version") or status.get("Version")
    mac = status_net.get("Mac") or status_net.get("MAC")
    wifi = status_sts.get("Wifi") or status_sts.get("Wifi1") or {}
    rssi = wifi.get("RSSI") if isinstance(wifi, dict) else None
    module = status_prm.get("Module") or status.get("Module")
    power = status_sts.get("POWER") or status_sts.get("POWER1") or status_sts.get("POWER2")
    uptime = status_sts.get("Uptime") or status_sts.get("UptimeSec")
    name = device_name or friendly_name or hostname or "Tasmota Geraet"

    return {
        "name": name,
        "hostname": hostname,
        "friendly_name": friendly_name,
        "device_name": device_name,
        "version": version,
        "mac": mac,
        "rssi": rssi,
        "module": module,
        "power": power,
        "uptime": uptime,
    }


def _pick_friendly_name(*sources: Dict) -> Optional[str]:
    for source in sources:
        fn = source.get("FriendlyName")
        if isinstance(fn, list) and fn:
            if fn[0]:
                return str(fn[0])
        elif isinstance(fn, str) and fn.strip():
            return fn.strip()
    return None


def _merge_device_infos(infos: List[Dict]) -> Dict:
    """
    Combine multiple status payloads, preferring the first non-empty value
    and replacing default placeholders.
    """
    merged: Dict = {}
    for info in infos:
        for key, val in info.items():
            if val in (None, "", []):
                continue
            if key not in merged or merged.get(key) in (None, "", [], "Tasmota Geraet"):
                merged[key] = val
    return merged
