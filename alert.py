import logging, json, time

#logging function
logging.basicConfig(
	filename='ids_alerts.log',
	level=logging.WARNING,
	format="%(asctime)s %(levelname)s %(message)s"
)

# function to log alerts
def alert(rule,src_ip,detail,severity=2):
	entry=json.dumps({
		'rule' : rule,
		'src': src_ip,
		'detail': detail,
		'severity': severity,
		'ts':time.time()
	})
	logging.warning(entry)
	print(f'[ALERT- {severity}] {rule} | {src_ip} | {detail}')

