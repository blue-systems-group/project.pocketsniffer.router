import time, json

import utils

class Client(object) :

  mac = None
  lastReport = None
  nearBy = None

  def __init__(self) :
    self.mac = None
    self.rx_bytes = None
    self.tx_bytes = None
    self.signal = None

    self.frequency = None
    self.neighbors = None
    self.channel_load = None

    self.last_updated = None

  def update_info(self, info) :
    self.rx_bytes = int(info['rx_bytes'])
    self.tx_bytes = int(info['tx_bytes'])
    self.signal = int(info['signal'])
    self.last_updated = time.time()

  def update_rf(self, msg) :
    utils.log("Updating RF condition for " + self.mac)

    self.frequency = int(msg['frequency'])
    self.neighbors = dict()
    self.channel_load = dict()

    for info in msg['traffics'] :
      utils.log(str(info))

      srcMac = info['srcMac']
      signal = int(info['signal'])
      channel = int(info['channel'])
      bytes = int(info['bytes'])

      if srcMac not in self.neighbors or signal > self.neighbors[srcMac] :
        self.neighbors[srcMac] = signal

      self.channel_load[channel] = self.channel_load.get(channel, 0) + bytes

    self.last_updated = time.time()
