# Intrusion Detection & Prevention System

A lightweight, raw-socket based IDS/IPS built in Python. It monitors network traffic in real time, detects common attack patterns, and can automatically block offending IPs at the firewall level.

## Features

- **Port Scan Detection** — flags a source IP once it probes too many distinct ports.
- **SSH Brute Force Detection** — flags repeated SSH connection attempts from the same IP within a time window.
- **ICMP Flood Detection** — flags abnormally high rates of ICMP echo requests (ping floods).
- **ARP Spoof Detection** — flags when a known IP's MAC address changes unexpectedly.
- **OS Fingerprinting** — makes a weighted guess at an attacker's OS based on TTL and TCP window size.
- **Multi-Stage Attack Correlation** — escalates to a critical alert if the same source IP triggers two or more different attack types within a short window.
- **Auto-Response (IPS)** — optionally blocks detected attackers using `iptables`, with automatic cleanup on shutdown.

## Files

| File | Purpose |
|---|---|
| `ids.py` | Main detection engine — captures and analyzes raw packets. |
| `alert.py` | Handles alert logging, cooldowns, and attack correlation. |
| `ips.py` | Handles automatic IP blocking/unblocking via `iptables`. |
| `requirements.txt` | Python dependencies. |

## Requirements

- Linux system (raw sockets require root/`AF_PACKET`)
- Python 3
- Root privileges to run

## Usage

**Log-only mode (default — no blocking):**
```bash
sudo python3 ids.py
```

**Enforce mode (actively blocks detected attackers):**
```bash
sudo python3 ids.py --enforce
```

**Manually unblock an IP:**
```bash
sudo python3 ips.py --unblock <ip>
```

## Safety Notes

- Blocking is **off by default**. It only activates with `--enforce`.
- A built-in allowlist prevents the system from ever blocking its own IP or the network gateway.
- All firewall rules added during a run are automatically removed on shutdown (`Ctrl+C`).
