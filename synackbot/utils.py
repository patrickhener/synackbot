import requests
import urllib.parse

from synackbot.config import PROXY, PROXY_PORT

def send_telegram(key,chat,message):
		escaped_message = urllib.parse.quote(str(message))
		send_text = 'https://api.telegram.org/bot' + key + '/sendMessage?chat_id=' + chat + '&text=' + escaped_message

		if PROXY:
			response = requests.get(send_text, verify=False, proxies={"https": f"http://127.0.0.1:{PROXY_PORT}"})
		else:
			response = requests.get(send_text, verify=False)

		return response


def choose_notification_message(n):
	msg = None

	if n['subject_type'] == "campaign":
		msg = f"New mission for target {n['subject']}, check bot output!"
	elif n['subject_type'] == "published":
		msg = f"New mission for target {n['subject']}, check bot output!"
	elif n['subject_type'] == "vulnerability":
		if n['action'] == "submitted":
			msg = f"Vulnerability '{n['subject']}' successfully submitted"
		elif n['action'] == "message":
			msg = f"There is a new message regarding vulnerability {n['subject']}"
		elif n['action'] == "accepted":
			msg = f"The vulnerability for {n['subject']} was accepted"
		elif n['action'] == "rejected":
			msg = f"Vulnerability '{n['subject']}' was rejected - Reason: {n['meta']['detailed_description']}"
		elif n['action'] == "edit":
			msg = f"Vulnerability '{n['subject']}' needs edits"
		else:
			msg = f"There was an unknown action type '{n['action']}' when trying to poll Notifications for a submission. See also bot.log."
	elif n['subject_type'] == "task":
		if n['action'] == "submitted":
			msg = f"Mission on '{n['subject']}' successfully submitted"
		elif n['action'] == "message":
			msg = f"There is a new message regarding mission {n['subject']}"
		elif n['action'] == "accepted":
			msg = f"The mission submission for {n['subject']} was accepted"
		elif n['action'] == "rejected":
			msg = f"Mission submission on '{n['subject']}' was rejected"
		elif n['action'] == "edit":
			msg = f"Mission submission on '{n['subject']}' needs edits"
		else:
			msg = f"There was an unknown action type '{n['action']}' when trying to poll Notifications for missions. See also bot.log."

	return msg