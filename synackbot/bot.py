import time
import os
import json
import signal
from datetime import datetime, timedelta

from synackbot.synack import Synack
from synackbot.utils import choose_notification_message, send_telegram
from synackbot.logging import log
from synackbot.static import MESSAGE_TEMPLATE, MISSION_TEMPLATE, TARGET_TEMPLATE
from synackbot.config import POLL_SLEEP,TELEGRAM_KEY,TELEGRAM_CHAT, CYCLE_TIMEOUT

RUN = True


def signal_handler(sig, frame):
	global RUN
	log.info("Caught CTRL+C, exiting ..")
	RUN = False


class Bot():
	def __init__(self):
		self.api = Synack()
		self.poll_sleep = POLL_SLEEP
		self.telegram_key = TELEGRAM_KEY
		self.telegram_chat = TELEGRAM_CHAT
		self.last_cycle_time = None
		self.cycle_timeout = CYCLE_TIMEOUT

	def connect(self):
		self.api.getSessionToken()
		self.api.getAssessments()

	def notification_send(self, message):
		resp = send_telegram(self.telegram_key, self.telegram_chat, message)
		if resp.status_code != 200:
			log.warning(f"Notification was not sent successful - {resp.status_code} - {resp.text}")

	def read_and_send_notifications(self):
		count = self.api.checkUnreadNotificationsCount()
		if count > 0:
			nots = self.api.pollNotifications()

			if len(nots) > 0:
				for n in nots:
					msg = choose_notification_message(n)
					if msg:
						self.notification_send(msg)

				self.api.markNotificationsRead()

	def read_and_send_messages(self):
		# First check unread message count
		count = self.api.checkUnreadMessageCount()
		if count > 0:
			mess = self.api.pollMessages()
			msg = None

			if len(mess) > 0:
				for m in mess:
					con = m['context']
					lis = con['listing']
					msg = MESSAGE_TEMPLATE % (con['type'], lis['codename'], con['vulnerability_title'], con['vulnerability_id'], m['subject'], m['preview'])

					self.notification_send(msg)

	def register_all_and_send(self):
		newly_registered = self.api.registerAll()
		if newly_registered == -1:
			self.notification_send("There is propably a lp+ target which did not register - review manually")
			return
		if len(newly_registered) > 0:
			print(f"bot received newly_registered with a length more than 0 and content: {newly_registered}")
			for i in newly_registered:
				print(f"now sending message for {i['codename']}")
				update_time = datetime.utcfromtimestamp(i['dateUpdated']).strftime("%Y-%m-%d %H:%M:%S")
				last_submit_time= datetime.utcfromtimestamp(i['lastSubmitted']).strftime("%Y-%m-%d %H:%M:%S")
				start_time= datetime.utcfromtimestamp(i['start_date']).strftime("%Y-%m-%d %H:%M:%S")
				end_time= datetime.utcfromtimestamp(i['end_date']).strftime("%Y-%m-%d %H:%M:%S")
				msg = TARGET_TEMPLATE % (i['category']['name'], i['organization']['name'],i['codename'],i['isUpdated'],update_time, i['isActive'], i['isNew'], i['averagePayout'], last_submit_time, start_time, end_time)

				log.info(f"Message is gonna be: {msg}")
				self.notification_send(msg)

	def claim_and_notify_missions(self):
		mission_json = self.api.pollMissions()
		if len(mission_json) == 0:
			return

		amount = self.api.getClaimThreshold()
		# log.info(f"We are able to claim a maximum of: {amount: .2f} $ worth missions")

		claimed_missions = self.api.claimMission(mission_json)
		if len(claimed_missions) > 0:
			for m in claimed_missions:
				if m['claimed']:
					msg = MISSION_TEMPLATE % (m['title'], m['categories'], m['asset_types'], m['organization'], m['listing'],m['payout'],m['finishing_time'])
					log.info(msg)
					self.notification_send(msg)

	def forever_loop(self):
		log.info("Starting the bot loop")
		self.display_or_change_target("optimusdownload")
		now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		self.notification_send(f"Bot started at {now}")



		signal.signal(signal.SIGINT, signal_handler)
		while True:
			if not RUN:
				break

			time.sleep(self.poll_sleep)
			self.claim_and_notify_missions()

			# Initial registration before timeout for cycle
			if not self.last_cycle_time:
				self.read_and_send_notifications()
				self.read_and_send_messages()
				self.register_all_and_send()
				self.last_cycle_time = datetime.now().replace(microsecond=0)
			else:
				now = datetime.now().replace(microsecond=0)
				if self.last_cycle_time < now - datetime.timedelta(seconds=self.cycle_timeout):
					self.read_and_send_notifications()
					self.read_and_send_messages()
					self.register_all_and_send()
					self.last_cycle_time = datetime.now().replace(microsecond=0)

		log.info("Bot exited gracefully - bye")

	def download_hydra(self, codename):
		if not codename:
			log.error("No codename was provided")
			return
		else:
			self.api.getAllTargets()
			json_response = self.api.getHydra(codename)
			hydraOut = list()
			for i in range(len(json_response)):
				keys = list(json_response[i]['ports'].keys())
				for j in range(len(keys)):
					portKeys = list(json_response[i]['ports'][keys[j]])
					for k in range(len(portKeys)):
						if len(json_response[i]['ports'][keys[j]][portKeys[k]]) > 0:
							hydraOut.append(json_response[i]['ip']+":"+keys[j]+":"+portKeys[k])

			with open(codename+"_hydra.out", "a") as out:
				out.write('\n'.join(hydraOut))


			log.info(f"Hydra successfully downloaded to {codename}_hydra.out")

	def download_analytics(self, codename):
		# TODO make synack getAnalytics to retrieve every analytics like in go bot
		if not codename:
			log.error("No codename was provided")
			return
		else:
			self.api.getAllTargets()
			analytics = self.api.getAnalytics(codename)
			with open(codename+"_analytics.out", mode='wt', encoding='utf-8') as out:
				json.dump(analytics, out)

			log.info(f"Analytics successfully downloaded to {codename}_analytics.out")

	def download_scope(self, codename):
		if not codename:
			log.error("No codename was provided")
			return
		else:
			self.api.getAllTargets()
			# First find category of target
			category = None

			slug = self.api.getTargetID(codename)
			if slug == "":
				log.error("Codename was not found")
				return

			for t in self.api.jsonResponse:
				if t['id'] == slug:
					category = t['category']['name']

			if not category:
				log.error("Category was not found")
				return

			if category == "Host":
				cidrs = self.api.getScope(codename)
				ips = self.api.getIPs(cidrs)
				targetPath = "./"+codename.upper()+"/"
				if os.path.isdir(targetPath) == False:
					os.mkdir(targetPath)
				filePath = "./"+codename.upper()+"/scope.txt"
				if os.path.exists(filePath):
					os.remove(filePath)
				with open('./'+codename.upper()+'/scope.txt', mode='wt', encoding='utf-8') as myfile:
					myfile.write('\n'.join(ips))
					myfile.write('\n')

			if category == "Web Application":
				tupleList = set()
				oosTupleList = set()
				burpSet = set()
				oosBurpSet = set()
				scope,oos = self.api.getScope(codename)

				wildcardRegex = "(.*\.|)"

				for j in range(len(scope)):
					netloc = scope[j]['netloc']
					path = scope[j]['netloc']
					wildcard = scope[j]['wildcard']
					path = scope[j]['path']
					netloc = netloc+path
					log.debug(netloc)
					if wildcard == True:
						tupleList.add(netloc)
						burpStr = netloc.replace('.','\.')
						burpStr = burpStr.replace('/','\/')
						burpSet.add(wildcardRegex + burpStr)
					else:
						tupleList.add(netloc)
						burpStr = netloc.replace('.','\.')
						burpStr = burpStr.replace('/','\/')
						burpSet.add(burpStr)

				for k in range(len(oos)):
					netloc = oos[k]['netloc']
					path = oos[k]['netloc']
					wildcard = oos[k]['wildcard']
					path = oos[k]['path']
					netloc = netloc + path
					oosTupleList.add(netloc)
					if wildcard == True:
						oosTupleList.add(netloc)
						oosBurpStr = netloc.replace('.','\.')
						oosBurpStr = oosBurpStr.replace('/','\/')
						oosBurpSet.add(wildcardRegex + oosBurpStr)
					else:
						oosBurpStr = netloc.replace('.','\.')
						oosBurpStr = oosBurpStr.replace('/','\/')
						oosTupleList.add(netloc)
						oosBurpSet.add(netloc.replace('.','\.'))

				scopeList = list(tupleList)
				burpList = list(burpSet)
				oosBurpList = list(oosBurpSet)
				targetPath = "./"+codename.upper()+"/"
				if os.path.isdir(targetPath) == False:
					os.mkdir(targetPath)
				filePath = "./"+codename.upper()+"/scope.txt"
				if os.path.exists(filePath):
					os.remove(filePath)

				with open('./'+codename.upper()+'/scope.txt', mode='wt', encoding='utf-8') as myfile:
					myfile.write('\n'.join(scopeList))
					myfile.write('\n')

				with open('./'+codename.upper()+'/burpScope.txt', mode='wt', encoding='utf-8') as myfile:
					myfile.write('\n'.join(burpList))
					myfile.write('\n')

				with open('./'+codename.upper()+'/burpOOS.txt', mode='wt', encoding='utf-8') as myfile:
					myfile.write('\n'.join(oosBurpList))
					myfile.write('\n')

			log.info(f"Scope successfully written to folder {codename.upper()}")

	def display_or_change_target(self, codename):
		self.api.getAllTargets()
		if not codename:
			slug = self.api.getCurrentTargetSlug()
			for t in self.api.jsonResponse:
				if t['id'] == slug:
					log.info(f"Currently you are connected to {t['codename'].upper()}")
					return
		else:
			self.api.connectToTarget(codename)
			log.info(f"Changed to target {codename.upper()}")
			return

	def display_transactions(self):
		self.api.getTransactions()
