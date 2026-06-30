import logging, json, time

logging.basicConfig(
	filename = 'ids_alerts.log',
	level = logging.WARNING,
	format = '%(asctime)s %(message)s'
)

def alert(rule, src_ip, detail, severity = 2):
	entry = json.dumps({
		'rule':     rule,
		'src':      src_ip,
		'detail':   detail,
		'severity': severity,
		'ts':       time.time()
	})
	logging.warning(entry)
	print(f'[ALERT-{severity}] {rule} | {src_ip} | {detail}')

