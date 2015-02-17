import threading
import json
import socket
import logging
import time
from collections import deque

import settings
from collector import get_station_dump


logger = logging.getLogger('pocketsniffer')

class MonitorThread(threading.Thread):

  def __init__(self, host=settings.SERVER_NAME, port=settings.PUBLIC_TCP_PORT, interval=settings.TRAFFIC_MONITOR_INTERVAL):
    super(MonitorThread, self).__init__()
    self.host = host
    self.port = port
    self.client_traffic = dict()
    self.intervalSec = interval

    self.window_size = 3

    logger.debug("%s started." % (self.__class__.__name__))


  def check(self):
    station_dump = get_station_dump()
    traffic = dict()

    for sta in station_dump['band2g'] + station_dump['band5g']:
      mac = sta['MAC']
      traffic[mac] = sta['rxBytes'] + sta['txBytes']

    for sta in self.client_traffic.keys():
      if sta not in traffic:
        del self.client_traffic[sta]

    for sta, bytes in traffic.items():
      if sta not in self.client_traffic:
        self.client_traffic[sta] = {'bytes': bytes, 'history': deque(maxlen=self.window_size), 'triggered': False}
      else:
        self.client_traffic[sta]['history'].append(bytes - self.client_traffic[sta]['bytes'])
        self.client_traffic[sta]['bytes'] = bytes


    stations = []

    for sta, stats in self.client_traffic.items():
      if len(stats['history']) < self.window_size:
        continue

      if not stats['triggered']:
        if all([t > settings.TRAFFIC_THRESHOLD for t in stats['history']]):
          stations.append(sta)
          stats['triggered'] = True
      else:
        if all([t < settings.TRAFFIC_THRESHOLD for t in stats['history']]):
          stats['triggered'] = False

    if len(stations) == 0:
      return

    logger.debug("Detected massive traffic from clients: %s" % (' '.join(stations)))

    msg = json.dumps({'action': 'triggerAlgorithm', 'clients': stations})
    try:
      conn = socket.create_connection((self.host, settings.PUBLIC_TCP_PORT), settings.CONNECTION_TIMEOUT_SEC*1000)
      conn.sendall(msg)
      conn.close()
    except:
      logger.exception("Failed to send msg.")

  def run(self):
    while True:
      try:
        self.check()
      except:
        logger.exception("Failed to check traffic.")

      try:
        time.sleep(self.intervalSec)
      except KeyboardInterrupt:
        break
      except:
        pass
