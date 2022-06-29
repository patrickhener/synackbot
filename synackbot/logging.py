import sys
import logging
import os

from logging.handlers import RotatingFileHandler

MAX_BYTES = 10000000 # Maximum size for a log file
BACKUP_COUNT = 9 # Maximum number of old log files

DEBUG = os.environ.get("DEBUG")

if DEBUG:
	FORMAT = '%(levelname).1s %(asctime)-15s '
	FORMAT += '%(filename)s:%(lineno)d %(message)s'
else:
	FORMAT = '%(levelname).1s %(asctime)-15s %(message)s'

log_format = logging.Formatter(FORMAT, datefmt="%Y-%m-%d %H:%M:%S")

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG if DEBUG else logging.INFO)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(log_format)
stream_handler.setLevel(logging.INFO)
stream_handler.setStream(sys.stdout)
log.addHandler(stream_handler)

info_handler = RotatingFileHandler('bot.log', maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT)
info_handler.setFormatter(log_format)
info_handler.setLevel(logging.INFO)
log.addHandler(info_handler)

error_handler = RotatingFileHandler('error.log', maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT)
error_handler.setFormatter(log_format)
error_handler.setLevel(logging.ERROR)
log.addHandler(error_handler)
