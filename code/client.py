import time, json

import utils, settings
from periodic import PeriodicTask

"""
Station
Obtained by 'iw station dump'
"""
class Client(object) :

  def __init__(self, mac) :
    self.mac = mac

    self.hostname = None
    self.ip = None
    self.rx_bytes = None
    self.tx_bytes = None
    self.signal = None

    self.frequency = None
    self.neighbors = None
    self.channel_load = None

    self.last_updated = None
    self.rf_last_updated = None

  """
  Update information from iw station dump
  """
  def update_info(self, info) :
    self.rx_bytes = int(info['rx_bytes'])
    self.tx_bytes = int(info['tx_bytes'])
    self.signal = int(info['signal'])
    self.last_updated = time.time()

  """
  Update RF condition from client's report
  """
  def update_rf(self, msg) :
    self.frequency = int(msg['frequency'])
    self.neighbors = dict()
    self.channel_load = dict()

    for info in msg['traffics'] :
      channel = int(info['channel'])
      if channel == 0 :
        continue

      srcMac = info['srcMac']
      signal = int(info['signal'])
      bytes = int(info['bytes'])

      if srcMac not in self.neighbors or signal > self.neighbors[srcMac] :
        self.neighbors[srcMac] = signal

      if srcMac != self.mac :
        self.channel_load[channel] = self.channel_load.get(channel, 0) + bytes

    self.rf_last_updated = time.time()


"""
Update station info at AP side
"""
class ClientTask(PeriodicTask) :

  def __init__(self) :
    super(ClientTask, self).__init__(settings.STATION_DUMP_INTERVAL_SEC)
    self.clients = dict()
    self.clients_lock = self.get_lock()

  def do_job(self) :
    with self.clients_lock :
      for mac, info in utils.get_station_info().items() :
        if mac not in self.clients :
          self.clients[mac] = Client(mac)

        self.clients[mac].update_info(info)

      for mac, info in utils.get_dhcp_list().items() :
        if mac not in self.clients :
          continue

        self.clients[mac].ip = info['ip']
        self.clients[mac].hostname = info['hostname']

      now = time.time()
      for mac, client in self.clients.items() :
        if now - client.last_updated > 3 * settings.STATION_DUMP_INTERVAL_SEC :
          self.log("Deleting " + mac)
          del self.clients[mac]

    self.log("Updated station list: %s" % (', '.join(self.clients.keys())))


  def update_rf(self, msg) :
    mac = msg['MAC']
    with self.clients_lock :
      if mac not in self.clients :
        self.clients[mac] = Client(mac)

      if 'traffics' in msg :
        self.log("Updating RF condition for " + mac)
        self.clients[mac].update_rf(msg)
