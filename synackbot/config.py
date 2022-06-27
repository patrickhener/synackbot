import configparser
import sys

from pathlib import Path
from os.path import exists
from synackbot.logging import log


config_file = str(Path.home())+"/.synack/synack.conf"
if not exists(config_file):
	log.error(f"File '{config_file}' does not exist - please setup")
	sys.exit()
config = configparser.ConfigParser()
config.read(config_file)

try:
	EMAIL = config['DEFAULT']['email']
	PASSWORD = config['DEFAULT']['password']
	LOGIN_WAIT = config['DEFAULT'].getint('login_wait',15)
	LOGIN_URL = config['DEFAULT']['login_url']
	AUTHY_SECRET = config['DEFAULT']['authy_secret']
	SESSION_TOKEN_PATH = config['DEFAULT'].get('session_token_path',"/tmp/synacktoken")
	NOTIFICATION_TOKEN_PATH = config['DEFAULT'].get('notification_token_path',"/tmp/notificationtoken")
	PROXY_PORT = config['DEFAULT'].getint('proxy_port',8080)
	PROXY = config['DEFAULT'].getboolean('proxy',False)
	POLL_SLEEP = config['DEFAULT'].getint('poll_sleep',10)
	TELEGRAM_KEY = config['DEFAULT']['telegram_key']
	TELEGRAM_CHAT = config['DEFAULT']['telegram_chat']
	CYCLE_TIMEOUT = config['DEFAULT'].getint('cycle_timeout', 300)
except KeyError as e:
	log.error(f"Missing key in config: {e}")
	sys.exit()
except BaseException as e:
	print(f"Basic exception {e} - quitting")
	sys.exit()