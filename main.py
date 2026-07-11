"""
FastAPI backend for the IDS Alert Dashboard.

Reads ids_alerts.log (JSON-lines written by your existing alert.py) and serves:

    GET  /            -> the dashboard frontend (static/index.html)
    GET  /api/alerts  -> recent alerts, newest first
    GET  /api/stats   -> summary counts (total, by_rule, by_severity)
    GET  /stream      -> Server-Sent Events, live alert push

Run this from the same directory as ids_alerts.log (i.e. ~/ids):

    pip install -r requirements.txt
    uvicorn main:app --host 127.0.0.1 --port 8000

Then open http://127.0.0.1:8000 in a browser. Run this alongside ids.py --
it only reads the log file, it never touches your sniffing/detection logic.
"""

import asyncio
import json
import queue
import threading
import time
from collections import deque, Counter
from pathlib import Path
import re
from fastapi import Request

from fastapi import FastAPI
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Config

ALERTS_FILE = Path("ids_alerts.log")   # same file alert.py's RotatingFileHandler writes
ALERTS_FILE.touch(exist_ok=True)
MAX_HISTORY = 500                      # how many recent alerts to keep in memory

app = FastAPI(title="IDS Alert Dashboard")

recent_alerts = deque(maxlen=MAX_HISTORY)
alerts_lock = threading.Lock()

clients = []            # one queue.Queue per connected SSE client
clients_lock = threading.Lock()

# Log parsing
OS_PATTERN = re.compile(r'\[suspected OS: ([^\]]+)\]')

def parse_line(line: str):
    try:
        idx = line.index("{")
        data = json.loads(line[idx:])
    except (ValueError, json.JSONDecodeError):
        return None

    match = OS_PATTERN.search(data.get("detail", ""))
    if match:
        data["os_guess"] = match.group(1)
        data["detail"] = OS_PATTERN.sub("", data["detail"]).strip()
    else:
        data["os_guess"] = None

    data.setdefault("sensor", "kali-sensor")
    return data

def load_existing():
    #On startup, load whatever's already in the log so the dashboard isn't empty.
    if not ALERTS_FILE.exists():
        return
    with open(ALERTS_FILE, "r") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                recent_alerts.append(parsed)


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
    data.setdefault("os_guess", None)

    with alerts_lock:
        recent_alerts.append(data)
    with clients_lock:
        for q in clients:
            q.put(data)

    print(f"[INGEST] sensor={data.get('sensor')} rule={data.get('rule')} "
          f"src={data.get('src')} detail={data.get('detail')}")

    return JSONResponse({"status": "ok"})

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
