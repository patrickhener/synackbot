import sys
# import signal
import traceback

import synackbot.env as env
from synackbot.args import parse_args
from synackbot.bot import Bot
from synackbot.utils import send_telegram


# def signal_handler(sig, frame):
# 	log.info("CTRL-C caught, exiting...")
# 	sys.exit()

class SynackBotApp(object):
	def __init__(self):
		assert env.synackbot_app is None, \
			"Instance of SynackBotApp already exists"
		env.synackbot_app = self

		self.args = parse_args()
		from synackbot.logging import log
		global log
		self.init_bot()

	def init_bot(self):
		self.bot = Bot()
		self.bot.connect()

	def run(self):
		if self.args.HYDRA:
			log.info("One-Shot action detected - executing")
			self.bot.download_hydra(self.args.CODENAME)
			sys.exit()
		elif self.args.ANALYTICS:
			log.info("One-Shot action detected - executing")
			self.bot.download_analytics(self.args.CODENAME)
			sys.exit()
		elif self.args.SCOPE:
			log.info("One-Shot action detected - executing")
			self.bot.download_scope(self.args.CODENAME)
			sys.exit()
		elif self.args.TARGET:
			log.info("One-Shot action detected - executing")
			self.bot.display_or_change_target(self.args.CODENAME)
			sys.exit()
		elif self.args.TRANSACTIONS:
			log.info("One-Shot action detected - executing")
			self.bot.display_transactions()
			sys.exit()
		else:
			# If not one shot start loop as thread
			# signal.signal(signal.SIGINT, signal_handler)
			try:
				self.bot.forever_loop()
				# signal.pause()
			except KeyboardInterrupt:
				self.bot.stop_flag = True
			except BaseException as e:
				traceback.print_exc()
				log.exception(e)
				send_telegram(self.bot.telegram_key, self.bot.telegram_chat, f"There was an exception. Bot has stopped: {e}")
