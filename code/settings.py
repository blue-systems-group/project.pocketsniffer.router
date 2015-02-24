import sys
import os
import json
import logging
from urllib2 import urlopen

SERVER_NAME = 'pocketsniffer.phone-lab.org'


"""Iperf port"""
IPERF_PORT_RANGE = (5555, 6666)


"""Heartbeat"""
HEARTBEAT_HOST = SERVER_NAME
HEARTBEAT_PATH = '/controller/heartbeat/ap'
HEARTBEAT_INTERVAL_SEC = 300


"""Parameters for socket connection/read."""
BUF_SIZE = 64*1024
CONNECTION_TIMEOUT_SEC = 10
READ_TIMEOUT_SEC = 10


"""Port for listening requests."""
PUBLIC_TCP_PORT = 7654
PUBLIC_BACKLOG = 10


"""Logging."""
LOGGING_FILE = "/var/log/pocketsniffer.log"
logging.basicConfig(filename=LOGGING_FILE, format='[%(asctime)s] %(levelname)s [%(filename)32s:%(lineno)4d] %(message)s', level=logging.DEBUG)
logger = logging.getLogger('pocketsniffer')

"""Monitor"""
TRAFFIC_MONITOR_INTERVAL = 1
TRAFFIC_THRESHOLD = 1024*1024/8


"""Hardware specs."""
VALID_2GHZ_CHANNELS = range(1, 12)
VALID_5GHZ_CHANNELS = range(36, 49, 4) + range(149, 166, 4)
VALID_CHANNELS = VALID_2GHZ_CHANNELS + VALID_5GHZ_CHANNELS

VALID_2GHZ_TXPOWER_DBM = range(1, 31)
VALID_5GHZ_TXPOWER_DBM = range(1, 18)
VALID_TXPOWER_DBM = set(VALID_2GHZ_TXPOWER_DBM + VALID_5GHZ_TXPOWER_DBM)



""" JSON schemas """
SCHEMA_BASE_URL = "http://pocketsniffer.phone-lab.org/static/schemas/"
self = sys.modules[__name__]
for attr, name in zip(['%s_SCHEMA' % (s) for s in ['REQUEST', 'REPLY', 'SCAN_RESULT', 'AP_STATUS', 'STATION_DUMP', 'TRAFFIC']],\
    ['%s.json' % (s) for s in 'request', 'reply', 'scanresult', 'ap-status', 'station-dump', 'traffic']):
  logger.debug("Parsing %s" % (os.path.join(SCHEMA_BASE_URL, name)))
  try:
    setattr(self, attr, json.loads(urlopen(os.path.join(SCHEMA_BASE_URL, name)).read()))
  except:
    logger.exception("Failed to parse %s" % (name))
    sys.exit()
