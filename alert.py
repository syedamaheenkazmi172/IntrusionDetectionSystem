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
# Set these two environment variables (on the Pi only) before running ids.py
# to forward every alert to Kali's dashboard in addition to local logging.
# Kali itself should NOT set these, so this file works unchanged on both
# machines without duplicating alerts.
#
#   export IDS_FORWARD_URL="http://192.168.100.25:8000/api/ingest"
#   export IDS_SENSOR_NAME="pi-sensor"
#
FORWARD_URL = os.environ.get("IDS_FORWARD_URL")
SENSOR_NAME = os.environ.get("IDS_SENSOR_NAME", "kali-sensor")
FORWARD_TIMEOUT = 2  # seconds, don't let a slow/dead Kali stall detection

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

        # forward to Kali's dashboard if configured (Pi-only in practice)
        if FORWARD_URL and requests is not None:
                try:
                        forward_payload = dict(payload)
                        forward_payload['sensor'] = SENSOR_NAME
                        requests.post(FORWARD_URL, json=forward_payload, timeout=FORWARD_TIMEOUT)
                except Exception as e:
                        print(f'[FORWARD-FAIL] could not reach {FORWARD_URL}: {e}')

	# don't let the composite alert trigger correlation
        if rule == 'MULTI_STAGE_ATTACK':
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
