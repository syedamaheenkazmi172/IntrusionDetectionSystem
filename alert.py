import logging, json, time, os
from logging.handlers import RotatingFileHandler
from collections import defaultdict

try:
    import requests
except ImportError:
    requests = None

# logging setup, rotates so the log file doesn't grow forever
handler = RotatingFileHandler('ids_alerts.log', maxBytes=5_000_000, backupCount=5)
logging.basicConfig(
        handlers=[handler],
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
) 
# use UTC so kali + pi timestamps match
logging.Formatter.converter = time.gmtime

# --- Remote forwarding (optional, off by default) ---
# Set these two environment variables before running ids.py *as a standalone
# sensor process* (whether that's the Pi, or a kali-sensor ids.py running as
# its own process on the same box as the dashboard) to forward every alert
# to the dashboard's /api/ingest in addition to local logging. Point
# IDS_FORWARD_URL at whatever host:port main.py is actually bound to -- e.g.
# Kali's Tailscale IP, not 127.0.0.1, if main.py isn't bound to loopback.
#
#   export IDS_FORWARD_URL="http://<dashboard-host>:8000/api/ingest"
#   export IDS_SENSOR_NAME="pi-sensor"      # or "kali-sensor"
#
# This is unrelated to _local_sink below: FORWARD_URL is for alert() calls
# happening in a SEPARATE process from the dashboard (any ids.py sensor);
# _local_sink is for alert() calls happening INSIDE the dashboard process
# itself (see set_local_sink docstring).
FORWARD_URL = os.environ.get("IDS_FORWARD_URL")
SENSOR_NAME = os.environ.get("IDS_SENSOR_NAME", "kali-sensor")
FORWARD_TIMEOUT = 2  # seconds, don't let a slow/dead dashboard stall detection

# --- In-process sink (used by main.py only) ---
# ips.unblock_ip() calls alert() directly. When that happens because ids.py
# (a separate process) hit SSH_BRUTE/ICMP_FLOOD, alert() should forward over
# HTTP like anything else. But main.py *also* calls unblock_ip() in-process
# when someone clicks "Unblock" on the dashboard -- and main.py IS the
# process serving /api/ingest. Looping back over HTTP to your own server
# from inside a request handler risks blocking that handler on itself.
# main.py registers a direct sink instead, so alerts generated inside its
# own process skip the network entirely and go straight into the db.
_local_sink = None


def set_local_sink(fn):
    """Register a callable(payload_dict) that main.py uses to insert alerts
    generated in its own process directly, bypassing HTTP forwarding."""
    global _local_sink
    _local_sink = fn

# tracks which rules each source ip has triggered recently, so we can
# spot multi-stage attacks
recent_alerts = defaultdict(list)   # src_ip
CORRELATION_WINDOW = 120            # seconds
# maps  own severity number to an actual logging level
LEVEL_MAP = {1: logging.INFO, 2: logging.WARNING, 3: logging.CRITICAL}
# keeps track of the last time we alerted for a given (rule, src_ip) pair
# so one scan doesn't spam 50 identical alerts in a second
last_alert = {}
COOLDOWN = 30  # seconds
# function to log alerts
def alert(rule, src_ip, detail, severity=2):
        key = (rule, src_ip)
        now = time.time()
        if now - last_alert.get(key, 0) < COOLDOWN:
                return
        last_alert[key] = now
        payload = {
                'rule': rule,
                'src': src_ip,
                'detail': detail,
                'severity': severity,
                'ts': now
        }
        entry = json.dumps(payload)
        logging.log(LEVEL_MAP.get(severity, logging.WARNING), entry)
        print(f'[ALERT-{severity}] {rule} | {src_ip} | {detail}')

        # main.py's own process gets alerts written straight to the db, no
        # network hop. Any other process (any ids.py sensor, local or remote)
        # forwards over HTTP to whichever dashboard IDS_FORWARD_URL points at.
        forward_payload = dict(payload)
        forward_payload['sensor'] = SENSOR_NAME
        if _local_sink is not None:
                try:
                        _local_sink(forward_payload)
                except Exception as e:
                        print(f'[LOCAL-SINK-FAIL] {e}')
        elif FORWARD_URL and requests is not None:
                try:
                        requests.post(FORWARD_URL, json=forward_payload, timeout=FORWARD_TIMEOUT)
                except Exception as e:
                        print(f'[FORWARD-FAIL] could not reach {FORWARD_URL}: {e}')

	# don't let the composite alert, or our own block/unblock bookkeeping,
	# feed back into correlation -- IP_BLOCKED/IP_UNBLOCKED are actions WE
	# took in response to an attack, not a new attack stage, so counting
	# them as a "distinct rule" was causing every real detection to falsely
	# combine with its own resulting block and fire MULTI_STAGE_ATTACK.
        if rule in ('MULTI_STAGE_ATTACK', 'IP_BLOCKED', 'IP_UNBLOCKED'):
                return
	# track this rule against the source ip, dropping anything outside the window
        recent_alerts[src_ip] = [
                (r, t) for r, t in recent_alerts[src_ip]
                if now - t < CORRELATION_WINDOW
        ]
        recent_alerts[src_ip].append((rule, now))
        distinct_rules = {r for r, t in recent_alerts[src_ip]}
        if len(distinct_rules) >= 2:
                combo = " + ".join(sorted(distinct_rules))
                alert('MULTI_STAGE_ATTACK', src_ip,
                      f'multiple attack types from same source: {combo}',
                      severity=3)
