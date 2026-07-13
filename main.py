"""
FastAPI backend for the IDS Alert Dashboard.

Reads ids_alerts.log (JSON-lines written by your existing alert.py) and serves:

    GET  /            -> the dashboard frontend (static/index.html)
    GET  /api/alerts  -> recent alerts, newest first (in-memory window)
    GET  /api/stats   -> summary counts (total, by_rule, by_severity)
    GET  /api/logs    -> searchable audit trail over the FULL on-disk log
    GET  /api/logs/export -> CSV/JSON download of the (filtered) audit trail
    GET  /api/timeseries  -> bucketed alert counts by severity, for the traffic chart
    GET  /api/blocked -> currently-blocked IPs
    POST /api/unblock -> unblock a locally-blocked IP
    POST /api/ingest  -> accepts alerts forwarded from remote sensors (e.g. the Pi)
    GET  /stream      -> Server-Sent Events, live alert push

Run this from the same directory as ids_alerts.log (i.e. ~/ids):

    pip install -r requirements.txt
    uvicorn main:app --host 127.0.0.1 --port 8000

Then open http://127.0.0.1:8000 in a browser. Run this alongside ids.py --
it only reads the log file, it never touches your sniffing/detection logic.
"""

import asyncio
import csv
import io
import json
import queue
import threading
import time
from collections import deque, Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import re

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

# unblock_ip is only safe to call when the block happened on THIS machine --
# see api_unblock() below for the local-vs-remote-sensor check
from ips import unblock_ip

# Config

ALERTS_FILE = Path("ids_alerts.log")   # same file alert.py's RotatingFileHandler writes
ALERTS_FILE.touch(exist_ok=True)
MAX_HISTORY = 500                      # how many recent alerts to keep in memory

# Sensor name that runs on the SAME machine as this dashboard, i.e. the one
# we're actually allowed to run `iptables -D` for. Matches alert.py's default
# SENSOR_NAME. When a Pi sensor is added later, its alerts arrive with
# sensor="pi-sensor" (or whatever IDS_SENSOR_NAME is set to) and won't match --
# unblocking those needs a remote control call, not built yet (see api_unblock).
LOCAL_SENSOR_NAME = "kali-sensor"

app = FastAPI(title="IDS Alert Dashboard")

recent_alerts = deque(maxlen=MAX_HISTORY)
alerts_lock = threading.Lock()

clients = []            # one queue.Queue per connected SSE client
clients_lock = threading.Lock()

# currently-blocked IPs, keyed by ip -> {sensor, reason, os_guess, ts}
# rebuilt from IP_BLOCKED/IP_UNBLOCKED events (see update_block_state)
blocked_state = {}
blocked_lock = threading.Lock()

# Log parsing
OS_PATTERN = re.compile(r'\[suspected OS: ([^\]]+)\]')
REASON_PATTERN = re.compile(r'triggered by ([A-Z_]+)')

def normalize_alert(data):
    """Shared post-processing for an alert dict, whether it came from the
    local log (parse_line) or a remote sensor (api_ingest)."""
    match = OS_PATTERN.search(data.get("detail", ""))
    if match:
        data["os_guess"] = match.group(1)
        data["detail"] = OS_PATTERN.sub("", data["detail"]).strip()
    else:
        data.setdefault("os_guess", None)

    data.setdefault("sensor", "kali-sensor")
    return data

def update_block_state(data):
    """Keep the blocked-IP panel in sync as IP_BLOCKED/IP_UNBLOCKED events
    flow through -- whether they came from the local log tail or a
    forwarded remote-sensor alert via /api/ingest."""
    rule = data.get("rule")
    ip = data.get("src")
    if not ip:
        return
    with blocked_lock:
        if rule == "IP_BLOCKED":
            reason_match = REASON_PATTERN.search(data.get("detail", ""))
            blocked_state[ip] = {
                "ip": ip,
                "sensor": data.get("sensor", "kali-sensor"),
                "reason": reason_match.group(1) if reason_match else None,
                "os_guess": data.get("os_guess"),
                "detail": data.get("detail"),
                "ts": data.get("ts", time.time()),
            }
        elif rule == "IP_UNBLOCKED":
            blocked_state.pop(ip, None)

def parse_line(line: str):
    try:
        idx = line.index("{")
        data = json.loads(line[idx:])
    except (ValueError, json.JSONDecodeError):
        return None
    return normalize_alert(data)

def read_all_alerts():
    """Read and parse the ENTIRE alert log from disk -- this is the real
    audit trail, independent of the in-memory recent_alerts cache (which
    is capped at MAX_HISTORY to keep the live view fast)."""
    if not ALERTS_FILE.exists():
        return []
    out = []
    with open(ALERTS_FILE, "r") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                out.append(parsed)
    return out


def filter_alerts(alerts, start=None, end=None, rule=None, severity=None,
                   src=None, sensor=None, q=None):
    def matches(a):
        ts = a.get("ts", 0)
        if start is not None and ts < start:
            return False
        if end is not None and ts > end:
            return False
        if rule and a.get("rule") != rule:
            return False
        if severity is not None and a.get("severity") != severity:
            return False
        if src and src not in (a.get("src") or ""):
            return False
        if sensor and a.get("sensor") != sensor:
            return False
        if q:
            haystack = " ".join(str(a.get(k, "")) for k in
                                 ("rule", "src", "detail", "sensor", "os_guess")).lower()
            if q.lower() not in haystack:
                return False
        return True
    return [a for a in alerts if matches(a)]


def load_existing():
    #On startup, load whatever's already in the log so the dashboard isn't empty.
    if not ALERTS_FILE.exists():
        return
    with open(ALERTS_FILE, "r") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                recent_alerts.append(parsed)
                update_block_state(parsed)


def tail_alerts():
    current_inode = ALERTS_FILE.stat().st_ino if ALERTS_FILE.exists() else None
    f = open(ALERTS_FILE, "r")
    f.seek(0, 2)  # jump to end -- only care about new lines from now on

    while True:
        line = f.readline()
        if line:
            parsed = parse_line(line)
            if parsed:
                with alerts_lock:
                    recent_alerts.append(parsed)
                update_block_state(parsed)
                with clients_lock:
                    for q in clients:
                        q.put(parsed)
        else:
            # check whether the log file got rotated out from under us
            try:
                new_inode = ALERTS_FILE.stat().st_ino
                if current_inode is not None and new_inode != current_inode:
                    f.close()
                    f = open(ALERTS_FILE, "r")
                    current_inode = new_inode
            except FileNotFoundError:
                pass
            time.sleep(0.5)


load_existing()
threading.Thread(target=tail_alerts, daemon=True).start()

# API routes

@app.get("/api/alerts")
def api_alerts():
    with alerts_lock:
        data = list(recent_alerts)[::-1]  # newest first
    return JSONResponse(data)


@app.get("/api/stats")
def api_stats():
    with alerts_lock:
        rule_counts = Counter(a.get("rule", "UNKNOWN") for a in recent_alerts)
        severity_counts = Counter(a.get("severity", 0) for a in recent_alerts)
        total = len(recent_alerts)
    return JSONResponse({
        "total": total,
        "by_rule": rule_counts,
        "by_severity": {str(k): v for k, v in severity_counts.items()},
    })


@app.post("/api/ingest")
async def api_ingest(request: Request):
    """
    Receives alerts forwarded from remote sensors (e.g. the Pi).
    Feeds them into the exact same store/broadcast pipeline as
    locally-detected alerts, so /api/alerts, /api/stats, and /stream
    all pick them up automatically.
    """
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)

    data.setdefault("sensor", "pi-sensor")
    data.setdefault("ts", time.time())
    data = normalize_alert(data)

    with alerts_lock:
        recent_alerts.append(data)
    update_block_state(data)
    with clients_lock:
        for q in clients:
            q.put(data)

    print(f"[INGEST] sensor={data.get('sensor')} rule={data.get('rule')} "
          f"src={data.get('src')} detail={data.get('detail')}")

    return JSONResponse({"status": "ok"})


@app.get("/api/blocked")
def api_blocked():
    with blocked_lock:
        data = sorted(blocked_state.values(), key=lambda b: b["ts"], reverse=True)
    return JSONResponse(data)


@app.post("/api/unblock")
async def api_unblock(request: Request):
    try:
        body = await request.json()
        ip = body["ip"]
    except Exception:
        return JSONResponse({"error": "expected {\"ip\": \"...\"}"}, status_code=400)

    with blocked_lock:
        entry = blocked_state.get(ip)

    if entry is None:
        return JSONResponse({"error": f"{ip} is not currently tracked as blocked"}, status_code=404)

    if entry.get("sensor") != LOCAL_SENSOR_NAME:
        # TODO: once a Pi sensor runs its own control endpoint, dispatch this
        # unblock request to that sensor over the network instead of erroring.
        return JSONResponse({
            "error": (
                f"{ip} was blocked by remote sensor '{entry.get('sensor')}'. "
                "Remote unblock isn't wired up yet -- run "
                f"'python3 ips.py --unblock {ip}' on that sensor directly."
            )
        }, status_code=501)

    unblock_ip(ip)  # this itself fires an IP_UNBLOCKED alert, which updates blocked_state
    return JSONResponse({"status": "ok", "ip": ip})


@app.get("/api/logs")
def api_logs(start: Optional[float] = None, end: Optional[float] = None,
             rule: Optional[str] = None, severity: Optional[int] = None,
             src: Optional[str] = None, sensor: Optional[str] = None,
             q: Optional[str] = None, limit: int = 500):
    """Searches the FULL on-disk log, not just the in-memory recent window --
    this is the audit-trail view for compliance/forensics, not the live feed."""
    alerts = read_all_alerts()
    matched = filter_alerts(alerts, start, end, rule, severity, src, sensor, q)
    matched.sort(key=lambda a: a.get("ts", 0), reverse=True)
    capped_limit = max(1, min(limit, 5000))
    return JSONResponse({
        "total_matched": len(matched),
        "returned": min(len(matched), capped_limit),
        "results": matched[:capped_limit],
    })


@app.get("/api/logs/export")
def api_logs_export(start: Optional[float] = None, end: Optional[float] = None,
                     rule: Optional[str] = None, severity: Optional[int] = None,
                     src: Optional[str] = None, sensor: Optional[str] = None,
                     q: Optional[str] = None, format: str = "csv"):
    """Downloadable export of the (optionally filtered) audit trail, for
    compliance/incident-report purposes."""
    alerts = read_all_alerts()
    matched = filter_alerts(alerts, start, end, rule, severity, src, sensor, q)
    matched.sort(key=lambda a: a.get("ts", 0))

    if format == "json":
        body = json.dumps(matched, indent=2)
        return Response(
            body, media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=ids_audit_log.json"}
        )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "time_utc", "severity", "rule", "src", "sensor", "os_guess", "detail"])
    for a in matched:
        ts = a.get("ts", 0)
        iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else ""
        writer.writerow([ts, iso, a.get("severity"), a.get("rule"), a.get("src"),
                          a.get("sensor"), a.get("os_guess"), a.get("detail")])
    return Response(
        buf.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ids_audit_log.csv"}
    )


@app.get("/api/timeseries")
def api_timeseries(hours: float = 6, bucket_seconds: int = 60):
    """Bucketed alert counts by severity, for the traffic-volume chart.
    Reads the full log (bounded to the requested time window) so the chart
    reflects real history, not just whatever's still in memory."""
    cutoff = time.time() - hours * 3600
    bucket_seconds = max(10, bucket_seconds)
    buckets = {}
    for a in read_all_alerts():
        ts = a.get("ts", 0)
        if ts < cutoff:
            continue
        bucket_t = int(ts // bucket_seconds) * bucket_seconds
        sev = a.get("severity", 2)
        entry = buckets.setdefault(bucket_t, {1: 0, 2: 0, 3: 0})
        if sev in entry:
            entry[sev] += 1

    points = [{"t": t, "info": v[1], "warn": v[2], "crit": v[3]}
              for t, v in sorted(buckets.items())]
    return JSONResponse({"bucket_seconds": bucket_seconds, "points": points})


@app.get("/stream")
async def stream():
    """
    SSE endpoint. Each connected browser tab gets its own queue; the
    tail_alerts() thread pushes into every queue when a new alert lands.

    asyncio.to_thread(q.get) blocks in a worker thread (not the event loop)
    until an item shows up, so this doesn't busy-poll or block other requests.
    """
    q = queue.Queue()
    with clients_lock:
        clients.append(q)

    async def event_generator():
        try:
            while True:
                alert = await asyncio.to_thread(q.get)
                yield f"data: {json.dumps(alert)}\n\n"
        finally:
            with clients_lock:
                if q in clients:
                    clients.remove(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# Frontend
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def index():
    return FileResponse("static/index.html")
