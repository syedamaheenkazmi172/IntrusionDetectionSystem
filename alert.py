import logging, json, time
from logging.handlers import RotatingFileHandler

# logging setup, rotates so the log file doesn't grow forever
handler = RotatingFileHandler('ids_alerts.log', maxBytes=5_000_000, backupCount=5)
logging.basicConfig(
        handlers=[handler],
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
) 

# use UTC so kali + pi timestamps match
logging.Formatter.converter = time.gmtime

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

        entry = json.dumps({
                'rule': rule,
                'src': src_ip,
                'detail': detail,
                'severity': severity,
                'ts': now
        })
        logging.log(LEVEL_MAP.get(severity, logging.WARNING), entry)
        print(f'[ALERT-{severity}] {rule} | {src_ip} | {detail}')
