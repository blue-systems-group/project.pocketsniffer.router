
import threading
import httplib
import json
import logging
import time

import settings
from collector import get_ap_status, get_ap_scan, get_station_dump


logger = logging.getLogger('pocketsniffer')

class HeartbeatThread(threading.Thread):

  def __init__(self, host=settings.HEARTBEAT_HOST, path=settings.HEARTBEAT_PATH, intervalSec=settings.HEARTBEAT_INTERVAL_SEC):
    super(HeartbeatThread, self).__init__()
    self.host = host
    self.path = path
    self.intervalSec = intervalSec


  def send_heartbeat(self):
    heartbeart = dict()
    heartbeart['apStatus'] = get_ap_status()
    heartbeart['apScan'] = get_ap_scan()
    heartbeart['stationDump'] = get_station_dump()
    logger.debug("Sending heartbeat: %s" % (json.dumps(heartbeart)))

    headers = {'Content-type': 'application/json'}


    try:
      conn = httplib.HTTPConnection(self.host, strict=True)
      conn.request('POST', self.path, json.dumps(heartbeart), headers)
      respose = conn.getresponse()
      if respose.status != httplib.OK:
        raise Exception(respose.reason)
      logger.debug("Successfully sent heartbeat to %s", self.host)
    except:
      logger.exception("Failed to send heartbeat.")


  def run(self):
    while True:
      try:
        self.send_heartbeat()
      except:
        logger.exception("Failed to send heartbeat.")
      try:
        time.sleep(self.intervalSec)
      except KeyboardInterrupt:
        break
      except:
        pass
