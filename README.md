# TasmotaFleet
Flask-App zum Auffinden von Tasmota-Geraeten im lokalen Netz. Sie scannt einen IP-Range auf den Ports 80 (HTTP) und 443 (HTTPS), fragt – wenn moeglich – die Status-API ab und listet die gefundenen Geraete auf dem Dashboard.

Der Quellcode liegt nun im Ordner `src/`.

## Features
- Scan eines IP-Ranges (CIDR oder Start–Ende) auf Port 80/443
- Erkennung ueber `/cm?cmnd=Status 0` bzw. `/cm?cmnd=Status 8` mit HTML-Fallback
- Anzeige von FriendlyName/Hostname, Version, MAC, RSSI, Power, Port/Protokoll
- Fortschrittsanzeige im UI (Progressbar + Polling) und Log-Ausgaben waehrend des Scans
- UI im Stil von PrintFleet/NeoFab mit Bootswatch Theme und Navbar-Scan-Button

## Setup
```bash
cd TasmotaFleet
python -m venv .venv
.venv\Scripts\activate        # PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Start
```bash
flask --app src.app run --host 0.0.0.0 --port 5000
# oder zum Entwickeln:
python -m src.app
```

Rufe danach `http://localhost:5000` im Browser auf.

## Konfiguration
- `TASMOTA_FLEET_RANGE` – Standard-IP-Range (Default: `192.168.1.0/24`)
- `SCAN_MAX_HOSTS` – maximale Hostanzahl pro Scan (Default: `512`)
- `SECRET_KEY` – Flask Secret fuer Sessions/Flash-Messages
- `SCAN_CACHE_FILE` – Pfad zur JSON-Datei mit den letzten Scan-Ergebnissen (Default: `scan_results.json`)

## Hinweise zum Scan
- TCP-Connect auf Port 80/443, danach Status-API. HTTPS wird ohne Zertifikatspruefung angesprochen, damit selbstsignierte Geraete erreichbar sind.
- Ergebnisse werden zusaetzlich in `scan_results.json` persistiert (per `SCAN_CACHE_FILE` konfigurierbar) und beim Start geladen, falls vorhanden.
