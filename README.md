![TasmotaFleet Logo](doku/Logo_TasmotaFleet.png)
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
apt install sudo -y
sudo apt update -y
sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-pip git

adduser tasmotafleet
su - tasmotafleet
mkdir -p ~/projects/tasmotafleet

cd projects/tasmotafleet

git clone https://github.com/know-how-schmiede/TasmotaFleet.git

cd TasmotaFleet
python3 -m venv .venv
source .venv/bin/activate        # PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Start
```bash
flask --app src.app run --host 0.0.0.0 --port 5000
# oder zum Entwickeln:
python -m src.app
```

Rufe danach `http://localhost:5000` im Browser auf.

## Als Dienst laufen lassen
```
source .venv/bin/activate
pip install gunicorn
```
Auf Root-User wechseln:
```
su - root
```
systemd Service anlegen (als root):
```
sudo nano /etc/systemd/system/tasmotafleet.service
```

```
[Unit]
Description=TasmotaFleet (Gunicorn)
After=network.target

[Service]
User=tasmotafleet
Group=tasmotafleet
WorkingDirectory=/home/tasmotafleet/projects/tasmotafleet/TasmotaFleet
Environment="PATH=/home/tasmotafleet/projects/tasmotafleet/TasmotaFleet/.venv/bin"
ExecStart=/home/tasmotafleet/projects/tasmotafleet/TasmotaFleet/.venv/bin/gunicorn -w 2 -b 0.0.0.0:5000 "src.app:create_app()"
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```
Dienst aktivieren und starten
```
sudo systemctl daemon-reload
sudo systemctl enable --now tasmotafleet
sudo systemctl status tasmotafleet --no-pager
```
Logs:
```
journalctl -u tasmotafleet -f
```

Reload + Neustart:
```
sudo systemctl daemon-reload
sudo systemctl restart tasmotafleet
sudo systemctl status tasmotafleet --no-pager
```

## TasmotaFleet updaten
Service stoppen (als root-User):
```
sudo systemctl stop tasmotafleet
```

Code aus GitHub aktualisieren:
```
su - tasmotafleet
cd projects/tasmotafleet/TasmotaFleet
git pull
```

Abhängigkeiten aktualisieren:
```
source .venv/bin/activate
pip install --upgrade pip
pip install --upgrade -r requirements.txt
su - root
```

Service wieder starten:
```
sudo systemctl start tasmotafleet
sudo systemctl status tasmotafleet --no-pager
```

## Konfiguration
- `TASMOTA_FLEET_RANGE` – Standard-IP-Range (Default: `192.168.1.0/24`)
- `SCAN_MAX_HOSTS` – maximale Hostanzahl pro Scan (Default: `512`)
- `SECRET_KEY` – Flask Secret fuer Sessions/Flash-Messages
- `SCAN_CACHE_FILE` – Pfad zur JSON-Datei mit den letzten Scan-Ergebnissen (Default: `scan_results.json`)
- Settings werden in `TasmotaFleetSet.JSON` gespeichert (Pfad per `TASMOTA_FLEET_SETTINGS` ueberschreibbar). Hier werden Standard-Range, Max Hosts, Cache-Pfad und Refresh-Intervall gesichert.

## Hinweise zum Scan
- TCP-Connect auf Port 80/443, danach Status-API. HTTPS wird ohne Zertifikatspruefung angesprochen, damit selbstsignierte Geraete erreichbar sind.
- Ergebnisse werden zusaetzlich in `scan_results.json` persistiert (per `SCAN_CACHE_FILE` konfigurierbar) und beim Start geladen, falls vorhanden.