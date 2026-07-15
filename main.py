"""
FastAPI backend for the IDS Alert Dashboard.

Alerts live in ids_alerts.db. 
Routes:

    GET  /            -> the dashboard frontend (static/index.html)
    GET  /api/alerts  -> most recent alerts, newest first
    GET  /api/stats   -> summary counts (total, by_rule, by_severity)
    GET  /api/logs    -> searchable audit trail over the FULL history
    GET  /api/logs/export -> CSV/JSON download of the (filtered) audit trail
    GET  /api/timeseries  -> bucketed alert counts by severity, for the chart
    GET  /api/blocked -> currently-blocked IPs
    POST /api/ingest  -> accepts alerts forwarded from any ids.py sensor
    GET  /stream      -> Server-Sent Events, live alert push

    This never touches detection logic, it only gets alerts getting generated from the ids.py
"""

import asyncio
import csv
import io
import json
import queue
import threading
import time
from datetime import datetime, timezone
from typing import Optional
import re

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

import db
import alert as alert_module

# Config

MAX_HISTORY = 500   # how many recent alerts /api/alerts returns by default

app = FastAPI(title="IDS Alert Dashboard")

clients = []            # one queue.Queue per connected SSE client
clients_lock = threading.Lock()

# currently-blocked IPs, keyed by ip -> {sensor, reason, os_guess, ts}
blocked_state = {}
blocked_lock = threading.Lock()

# Alert normalization
OS_PATTERN = re.compile(r'\[suspected OS: ([^\]]+)\]')
REASON_PATTERN = re.compile(r'triggered by ([A-Z_]+)')

def normalize_alert(data):
    """Shared post-processing for an alert dict, wherever it came from."""
    match = OS_PATTERN.search(data.get("detail", ""))
    if match:
        data["os_guess"] = match.group(1)
        data["detail"] = OS_PATTERN.sub("", data["detail"]).strip()
    else:
        data.setdefault("os_guess", None)

    data.setdefault("sensor", "kali-sensor")
    data.setdefault("ts", time.time())
    return data


def update_block_state(data):
    """Keep the blocked-IP panel in sync as IP_BLOCKED events flow through, whether from startup replay or a live ingest."""
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


def ingest_alert(data):
    """The one place alerts get written: normalize -> persist to db ->
    update the blocked-IP panel -> broadcast to connected SSE clients.
    Called both by POST /api/ingest (any ids.py sensor, local or remote)
    and by alert.py's local sink (alerts generated in this process itself).
    """
    data = normalize_alert(data)
    db.insert_alert(data)
    update_block_state(data)
    with clients_lock:
        for q in clients:
            q.put(data)
    return data


def _startup():
    db.init_db()
    # rebuild the blocked-IP panel by replaying history, oldest first
    for event in db.blocked_events():
        update_block_state(event)
    # alerts generated inside THIS process (e.g. the Unblock button) go
    # straight to ingest_alert, no HTTP loopback -- see alert.py
    alert_module.set_local_sink(ingest_alert)


_startup()

# API routes

@app.get("/api/alerts")
def api_alerts():
    return JSONResponse(db.recent_alerts(MAX_HISTORY))


@app.get("/api/stats")
def api_stats():
    return JSONResponse(db.stats())


@app.post("/api/ingest")
async def api_ingest(request: Request):
    """
    Receives alerts forwarded from any ids.py sensor (local or remote).
    Feeds them into the same ingest_alert() pipeline as locally-generated
    alerts, so /api/alerts, /api/stats, and /stream all pick them up.
    """
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)

    data.setdefault("sensor", "unknown-sensor")
    data.setdefault("ts", time.time())
    data = ingest_alert(data)

    print(f"[INGEST] sensor={data.get('sensor')} rule={data.get('rule')} "
          f"src={data.get('src')} detail={data.get('detail')}")

    return JSONResponse({"status": "ok"})


@app.get("/api/blocked")
def api_blocked():
    with blocked_lock:
        data = sorted(blocked_state.values(), key=lambda b: b["ts"], reverse=True)
    return JSONResponse(data)


# NOTE: there is intentionally no POST /api/unblock here anymore. Unblocking
# now only happens two ways:
#   1. Automatically, when ids.py on a sensor shuts down (unblock_all() in
#      ips.py's signal handler).
#   2. Manually, by running `python3 ips.py --unblock <ip>` directly on the
#      sensor that holds the block (the Pi, most of the time).
# The dashboard is read-only with respect to blocking: it can show you
# what's blocked (GET /api/blocked below) but can't unblock it.


@app.get("/api/logs")
def api_logs(start: Optional[float] = None, end: Optional[float] = None,
             rule: Optional[str] = None, severity: Optional[int] = None,
             src: Optional[str] = None, sensor: Optional[str] = None,
             q: Optional[str] = None, limit: int = 500):
    """Searches the FULL history via an indexed query -- the audit-trail view
    for compliance/forensics, not just the in-memory live window."""
    capped_limit = max(1, min(limit, 5000))
    total, matched = db.query_alerts(start, end, rule, severity, src, sensor, q,
                                      limit=capped_limit)
    return JSONResponse({
        "total_matched": total,
        "returned": len(matched),
        "results": matched,
    })


@app.get("/api/logs/export")
def api_logs_export(start: Optional[float] = None, end: Optional[float] = None,
                     rule: Optional[str] = None, severity: Optional[int] = None,
                     src: Optional[str] = None, sensor: Optional[str] = None,
                     q: Optional[str] = None, format: str = "csv"):
    """Downloadable export of the (optionally filtered) audit trail, for
    compliance/incident-report purposes."""
    matched = db.query_alerts_for_export(start, end, rule, severity, src, sensor, q)

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
    """Bucketed alert counts by severity, for the traffic-volume chart."""
    used_bucket_seconds, points = db.timeseries(hours=hours, bucket_seconds=bucket_seconds)
    return JSONResponse({"bucket_seconds": used_bucket_seconds, "points": points})


@app.get("/stream")
async def stream():
    """
    SSE endpoint. Each connected browser tab gets its own queue; ingest_alert()
    pushes into every queue when a new alert lands.

    asyncio.to_thread(q.get) blocks in a worker thread (not the event loop)
    until an item shows up, so this doesn't busy-poll or block other requests.
    """
    q = queue.Queue()
    with clients_lock:
        clients.append(q)

    async def event_generator():
        try:
            while True:
                item = await asyncio.to_thread(q.get)
                yield f"data: {json.dumps(item)}\n\n"
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
