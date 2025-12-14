# TasmotaFleet – Dein Radar f"ur Tasmota-Ger"ate im Netzwerk

TasmotaFleet ist eine kleine, schnelle Web-App, die dein LAN nach Tasmota-Ger"aten scannt und die Ergebnisse "ubersichtlich im Browser zeigt. Ohne MQTT-Setup, ohne Agent auf den Ger"aten: IP-Bereich eingeben, Scan starten, fertig.

## Warum TasmotaFleet?
- **Zero-Config**: Ein HTTP-Scan holt Status-Infos direkt von den Tasmota-APIs (Status 0/8).
- **Schnell"ubersicht**: Tabelle mit Name/Hostname, IP/Port, Firmware-Version, MAC, RSSI und Power-Status.
- **Auto-Refresh**: Live-Updates halten die Werte (z. B. RSSI/Power) aktuell.
- **Cachen & Fortsetzen**: Letztes Scan-Ergebnis wird gespeichert und beim Start geladen.
- **Fehlerrobust**: Zeitouts, 404er und teildefekte Ger"ate bremsen den Scan nicht aus.

## So funktioniert der Scan
1. IP-Bereich per CIDR (z. B. `192.168.1.0/24`) oder Range angeben.
2. Ports w"ahlen (Default: 80/443).
3. Scan starten: TasmotaFleet pr"uft offene Ports und holt Status-JSON.
4. Ergebnisse erscheinen sofort in der Tabelle; das Web-UI ist per Klick erreichbar.

## Highlights f"ur Admins
- **Direkter Gerätestatus**: RSSI, Power, Firmware-Version ohne SSH oder MQTT.
- **Hostname aus dem Device**: Keine Reverse-DNS-Abh"angigkeit; der Hostname kommt aus `StatusNET.Hostname`.
- **DeviceName & FriendlyName**: Zeigt den benutzerdefinierten Namen (z. B. `TasmotaQ5`) neben dem Hostnamen.
- **Logging**: Nach jedem Scan werden Name + IP/Port geloggt; optionales Debug-Logging f"ur tiefergehende Analysen.

## Quickstart
```bash
git clone <repo-url>
cd TasmotaFleet
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
flask run
```

Öffne `http://127.0.0.1:5000`, w"ahle deinen IP-Range und starte den Scan.

## Metatags / Hashtags
- Meta: TasmotaFleet, Tasmota Scanner, Netzwerk Scan, IoT Discovery, Flask App
- Tags: #Tasmota #HomeAutomation #IoT #NetworkScan #OpenSource
