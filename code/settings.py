import sys
import os
import json
import logging
from urllib2 import urlopen


"""IP and port for listening client reply."""
LOCAL_IP = '192.168.1.1'
LOCAL_TCP_PORT = 6543
LOCAL_BACKLOG = 10

"""The port that pocketsniffer app listens on."""
CLIENT_TCP_PORT = 6543


"""Parameters for socket connection/read."""
BUF_SIZE = 64*1024
CONNECTION_TIMEOUT_SEC = 10
READ_TIMEOUT_SEC = 10

"""Port for listening controller collector requests."""
PUBLIC_TCP_PORT = 7654
PUBLIC_BACKLOG = 10

"""Port for client throughput test."""
HTTP_PORT = 8080


logging.basicConfig(filename='pocketsniffer.log', format='[%(asctime)s] %(levelname)s [%(filename)32s:%(lineno)4d] %(message)s', level=logging.DEBUG)


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
  setattr(self, attr, json.loads(urlopen(os.path.join(SCHEMA_BASE_URL, name)).read()))
