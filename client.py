import time

class Client(object) :

  mac = None
  lastReport = None
  nearBy = None

  def __init__(self) :
    self.mac = None
    self.rx_bytes = None
    self.tx_bytes = None
    self.signal = None
    self.last_updated = None

  @classmethod
  def create(cls, mac, info) :
    client = Client()
    client.mac = mac
    client.rx_bytes = int(info['rx_bytes'])
    client.tx_bytes = int(info['tx_bytes'])
    client.signal = int(info['signal'])
    client.last_updated = time.time()

    return client
    

  def update_info(self, info) :
    pass

  def update_rf(msg) :
    pass
