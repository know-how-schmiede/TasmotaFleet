# TasmotaFleet Setup (Debian 13 LXC)

This guide is for Linux beginners. All commands are run inside the Debian 13 LXC
container as `root`.

## 1) Update system and install git

```bash
apt update && apt -y upgrade
apt -y install git
```

## 2) Clone the repository

```bash
git clone https://github.com/know-how-schmiede/TasmotaFleet.git /opt/tasmotafleet
cd /opt/tasmotafleet/scripts
```

## 3) Make scripts executable

```bash
chmod +x setupTasmotaFleet setupTasmotaFleetService updateTasmotaFleetService
```

## 4) Install and test (recommended)

Run the setup script and press Enter to accept defaults:

```bash
./setupTasmotaFleet
```

The script can start a test run. Open the web UI:

```
http://<container-ip>:8080
```

Stop the test with Ctrl+C.

## 5) Install the service (after the test)

```bash
./setupTasmotaFleetService
```

Check status:

```bash
systemctl status tasmotafleet
```

## 6) Update later (recommended)

```bash
./updateTasmotaFleetService
```

## Notes

- If you changed the repo path, use that path when asked.
- The scripts use safe defaults and ask only a few questions.
- systemd must be available in the container to run the service.
