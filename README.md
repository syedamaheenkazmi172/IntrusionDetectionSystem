# Intrusion Detection & Prevention System

A lightweight IDS/IPS built in Python with a live web dashboard. A sensor process reads
raw packets off the wire, detects common attack patterns, and can automatically block
offending IPs at the firewall level. A FastAPI backend collects alerts from the sensor
and serves a real-time console for monitoring and forensics.

**Team**
<table>
  <tr>
    <td align="center">
      <a href="https://github.com/Usman-Azhar">
        <b>Usman Azhar</b>
    </td>
    <td align="center">
      <a href="https://github.com/syedamaheenkazmi172">
        <b>Syeda Maheen Kazmi</b>
    </td>
  </tr>
</table>

## Deployment used in this project

| Role | Device | Runs |
|---|---|---|
| Sensor + enforcement point | Raspberry Pi | `ids.py` (raw packet capture, detection, `iptables` blocking) |
| Attacker | Kali Linux | `nmap`, `hydra`, `ping -f`, `arpspoof`, etc. — generates the traffic the Pi detects |
| Dashboard | Kali Linux | `main.py` (FastAPI backend + live web console) |

The Pi watches its own network interface, detects attacks coming from Kali, and forwards
every alert over HTTP to the dashboard running on Kali itself. The dashboard is only a
viewer/collector — it never touches packets and has no detection logic of its own.

```
 ┌──────────────────────┐   attack traffic     ┌──────────────────────┐
 │   Kali (attacker)    │ ───────────────────▶ │   Raspberry Pi       │
 │  nmap / hydra / ping │   (nmap, hydra,      │   sensor: ids.py     │
 │  -f / arpspoof ...   │    ping flood, ...)  │   + iptables (IPS)   │
 └─────────┬────────────┘                      └──────────┬───────────┘    
           │                                               │ alert()
           │  http://<kali-ip>:8000/api/ingest             │ POST /api/ingest
           │◀──────────────────────────────────────────────┘
           ▼
 ┌──────────────────────────────────────────┐
 │   Kali (dashboard host)                  │
 │   main.py (FastAPI) ──▶ ids_alerts.db    │
 │        │                                 │
 │        └── SSE /stream ──▶ browser       │
 │             static/index.html            │
 └──────────────────────────────────────────┘
```

Because Kali is both the attacker *and* the dashboard host, the browser showing the
live console and the machine generating the attacks are the same box — the Pi is the
only thing doing actual detection and blocking.

## Features

**Detection engine (`ids.py`, runs on the Pi)**
- **Port Scan Detection** — flags a source IP once it probes too many distinct ports (e.g. an `nmap` scan from Kali).
- **SSH Brute Force Detection** — flags repeated SSH connection attempts from the same IP within a time window (e.g. `hydra` from Kali).
- **ICMP Flood Detection** — flags abnormally high rates of ICMP echo requests (e.g. `ping -f` from Kali).
- **ARP Spoof Detection** — flags when a known IP's MAC address changes unexpectedly.
- **OS Fingerprinting** — makes a weighted guess at an attacker's OS from TTL and TCP window size (should correctly guess "Linux" for Kali).
- **Multi-Stage Attack Correlation** — escalates to a critical alert if Kali triggers two or more different attack types within a short window.
- **Auto-Response (IPS)** — optionally blocks Kali's IP on the Pi using `iptables`, with automatic cleanup on shutdown.

**Dashboard (`main.py`, runs on Kali)**
- Live alert feed pushed over Server-Sent Events — no polling, no refresh.
- Summary stats (totals, breakdown by rule and severity) and a bucketed traffic-volume chart.
- Searchable audit-trail log (`/api/logs`) with CSV/JSON export for incident reports.
- Blocked-IP panel, kept in sync automatically as the Pi blocks/unblocks.

## Files

| File | Purpose |
|---|---|
| `ids.py` | Detection engine — captures and analyzes raw packets, runs each detection rule. Runs on the **Pi**. |
| `alert.py` | Alert logging, per-rule cooldowns, multi-stage correlation, and forwarding to the dashboard. |
| `ips.py` | Automatic IP blocking/unblocking via `iptables`, plus a standalone CLI for manual control. Runs on the **Pi**. |
| `main.py` | FastAPI backend — ingests alerts, persists them, and serves the dashboard/API. Runs on **Kali**. |
| `db.py` | SQLite storage layer (schema, inserts, filtered/paginated queries, CSV/JSON export). |
| `static/index.html` | Single-page live dashboard (alert feed, stats, chart, audit log, blocked IPs). |
| `requirements.txt` | Python dependencies for the dashboard. |

## Requirements

- Raspberry Pi running Linux, with root access (raw sockets require `AF_PACKET`)
- Kali Linux (attacker + dashboard host)
- Python 3.9+ on both machines
- Both machines on the same network, Pi's target-facing interface reachable from Kali

## Setup

On **both** the Pi and Kali:
```bash
python3 -m venv ids_env
source ids_env/bin/activate
pip install -r requirements.txt
```

## Usage

**1. On Kali — start the dashboard:**
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```
Open `http://<kali-ip>:8000` in a browser (also on Kali, since it's hosting it).

**2. On the Pi — point the sensor at Kali's dashboard and start it:**
```bash
export IDS_FORWARD_URL="http://<kali-ip>:8000/api/ingest"
export IDS_SENSOR_NAME="pi-sensor"
sudo python3 ids.py --enforce
```
Drop `--enforce` for a dry run that only logs and alerts without touching `iptables`.

**3. On Kali — generate attack traffic against the Pi**, e.g.:
```bash
nmap -sS <pi-ip>                      # port scan
hydra -l pi -P wordlist.txt ssh://<pi-ip>   # SSH brute force
ping -f <pi-ip>                       # ICMP flood
arpspoof -i <iface> -t <pi-ip> <gateway-ip> # ARP spoof
```
Each of these should show up live on the dashboard within a few seconds, and
`--enforce` mode will get Kali's IP blocked on the Pi once a rule's threshold is hit.

**Manually unblock Kali's IP on the Pi if needed:**
```bash
sudo python3 ips.py --unblock <kali-ip>
sudo python3 ips.py --list      # see current DROP rules
```

## API

| Endpoint | Description |
|---|---|
| `GET /api/alerts` | Most recent alerts, newest first. |
| `GET /api/stats` | Summary counts — total, by rule, by severity. |
| `GET /api/logs` | Searchable audit trail over full history (filters: `start`, `end`, `rule`, `severity`, `src`, `sensor`, `q`). |
| `GET /api/logs/export` | CSV/JSON download of the (filtered) audit trail. |
| `GET /api/timeseries` | Bucketed alert counts by severity, for the traffic-volume chart. |
| `GET /api/blocked` | Currently-blocked IPs. |
| `POST /api/ingest` | Accepts alerts forwarded from the Pi sensor. |
| `GET /stream` | Server-Sent Events — live alert push to the dashboard. |

## Safety Notes

- Blocking is **off by default** on the Pi. It only activates with `--enforce`.
- A built-in allowlist (`ALLOWLIST` in `ips.py`) prevents the Pi from ever blocking allowlisted IPs — add Kali's IP here temporarily if you need uninterrupted testing.
- All firewall rules the Pi adds during a run are automatically removed on shutdown (`Ctrl+C`).
- The dashboard on Kali is read-only with respect to blocking — it can show what's currently blocked on the Pi but can't issue an unblock itself.

## Disclaimer

Built as a learning project to explore raw-socket packet parsing, network intrusion
detection, and firewall automation. Only run the attacker steps above against machines
you own, on a network you control.
