import json
import re
import socket
import threading
import traceback

import utils
import settings
from common import Result


class AccessPoint(object):
  """Scan result entry.

  Collected from the output of `iw wlan0 scan`.
  """

  IW_SCAN_PATTERNS = {
      'SSID': re.compile(r"""^SSID:\s(?P<SSID>.*)$""", re.MULTILINE),
      'BSSID': re.compile(r"""^BSS\s(?P<BSSID>[:\w]{17})\(on\swlan\d\)$""", re.MULTILINE),
      'channel': re.compile(r"""^freq:\s(?P<channel>\d{4})$""", re.MULTILINE),
      'signal': re.compile(r"""^signal:\s(?P<signal>[-\d]*?)\.00 dBm$""", re.MULTILINE),
      'client_num': re.compile(r"""^\*\sstation\scount:\s(?P<client_num>\d*)$""", re.MULTILINE),
      'utilization': re.compile(r"""^\*\schannel\sutili[sz]ation:\s(?P<utilization>\d*\/\d*)$""", re.MULTILINE),
      }


  def __init__(self):
    [setattr(self, attr, None) for attr in AccessPoint.IW_SCAN_PATTERNS.keys()]

  @classmethod
  def single_create(cls, lines):
    """Create one scan result entry.
    """
    ap = AccessPoint()
    output = '\n'.join([l.strip() for l in lines])
    for attr, pattern in cls.IW_SCAN_PATTERNS.items() :
      match = pattern.search(output)
      if match is not None:
        setattr(ap, attr, match.group(attr))

    # fix utilizations, convert xx/255 to float
    if ap.utilization is not None:
      ap.utilization = int(1000*float(ap.utilization.split('/')[0]) / float(ap.utilization.split('/')[1]))/1000.0

    return ap

  @classmethod
  def bulk_create(cls, lines):
    index = [i for i in xrange(0, len(lines)) if lines[i].startswith('BSS ')] + [len(lines)]
    return [AccessPoint.single_create(lines[i:j]) for i, j in zip(index[:-1], index[1:])]

  @classmethod
  def collect(cls, iface='wlan0'):
    aps = cls.bulk_create(utils.scan(iface).split('\n'))

    for ap in aps:
      setattr(ap, 'iface', iface)
    return aps

  def __str__(self):
    return json.dumps(self.__dict__)

  def __repr__(self):
    return self.__str__()




class Station(object):
  """Devices that associate with this AP.

  Collected from `iw wlan0 station dump`. Extra information, such as client's scan
  results and traffic condition may also be available.
  """


  IW_STATION_DUMP_PATTERNS = {
      'MAC': re.compile(r"""^Station\s(?P<MAC>[:\w]{17})\s\(on\swlan\d\)$""", re.MULTILINE),
      'inactive_time': re.compile(r"""^inactive\stime:\s*(?P<inactive_time>\d*)\sms$""", re.MULTILINE),
      'rx_bytes': re.compile(r"""^rx\sbytes:\s*(?P<rx_bytes>\d*)$""", re.MULTILINE),
      'rx_packets': re.compile(r"""^rx\spackets:\s*(?P<rx_packets>\d*)$""", re.MULTILINE),
      'tx_bytes': re.compile(r"""^tx\sbytes:\s*(?P<tx_bytes>\d*)$""", re.MULTILINE),
      'tx_packets': re.compile(r"""^tx\spackets:\s*(?P<tx_packets>\d*)$""", re.MULTILINE),
      'tx_retries': re.compile(r"""^tx\sretries:\s*(?P<tx_retries>\d*)$""", re.MULTILINE),
      'tx_failed': re.compile(r"""^tx\sfailed:\s*(?P<tx_failed>\d*)$""", re.MULTILINE),
      'signal_avg': re.compile(r"""^signal\savg:\s*(?P<signal_avg>-\d*).*$""", re.MULTILINE),
      'tx_bitrate': re.compile(r"""^tx\sbitrate:\s*(?P<tx_bitrate>[\d\.]*).*$""", re.MULTILINE),
      'rx_bitrate': re.compile(r"""^rx\sbitrate:\s*(?P<rx_bitrate>[\d\.]*).*$""", re.MULTILINE),
      }

  DHCP_LEASES_PATTERNS = re.compile(r"""^\d*\s(?P<MAC>[:\w]{17})\s(?P<IP>[\d\.]{7,15})\s(?P<hostname>[\w-]*?)\s.*$""", re.MULTILINE)

  def __init__(self):
    [setattr(self, attr, None) for attr in Station.IW_STATION_DUMP_PATTERNS.keys()]

  def set_scan_results(self, iw_scan_output):
    aps = AccessPoint.bulk_create(iw_scan_output.split('\n'))
    setattr(self, 'scan_result', aps)

  def set_traffic(self, traffic):
    setattr(self, 'traffic', traffic)

  @classmethod
  def single_create(cls, lines):
    sta = Station()
    output = '\n'.join([l.strip() for l in lines])
    for attr, pattern in cls.IW_STATION_DUMP_PATTERNS.items():
      match = pattern.search(output)
      if match is not None:
        setattr(sta, attr, match.group(attr))

    return sta

  @classmethod
  def bulk_create(cls, lines):
    index = [i for i in xrange(0, len(lines)) if lines[i].startswith('Station ')] + [len(lines)]
    return [Station.single_create(lines[i:j]) for i, j in zip(index[:-1], index[1:])]

  @classmethod
  def collect(cls, iface='wlan0'):
    stas = dict((sta.MAC, sta) for sta in cls.bulk_create(utils.station_dump(iface).split('\n')))

    for sta in stas.values():
      setattr(sta, 'iface', iface)

    with open('/var/dhcp.leases') as f :
      for line in f.readlines():
        match = Station.DHCP_LEASES_PATTERNS.match(line)
        if match is not None and match.group('MAC') in stas:
          [setattr(stas[match.group('MAC')], attr, match.group(attr)) for attr in ['hostname', 'IP']]

    return stas.values()

  def __str__(self):
    return json.dumps(self.__dict__)

  def __repr__(self):
    return self.__str__()




class HandlerThread(threading.Thread):
  """ Handler thread for replies from clients.
  """

  def __init__(self, conn, client):
    super(HandlerThread, self).__init__()
    self.conn = conn
    self.client = client

  def run(self):
    try:
      self.conn.settimeout(settings.READ_TIMEOUT_SEC)
      reply = json.loads(utils.recv_all(self.conn))
      self.conn.close()
    except:
      utils.log("Failed to decode client reply.")
      traceback.print_exc(settings.LOG_FILE)
      return

    utils.log("Got reply from %s (%s)" % (self.client.MAC, self.client.IP))
    try:
      if 'scan_result' in reply:
        self.client.set_scan_results(reply['scanResult']['output'])
      if 'traffic' in reply:
        self.client.set_traffic(reply['traffic'])
    except:
      utils.log("Failed to set scan results or traffic.")
      traceback.print_exc(settings.LOG_FILE)



class CollectorResult(Result):

  def __init__(self, request):
    super(CollectorResult, self).__init__(request)
    for attr in ['neighbor_aps', 'clients']:
      setattr(self, attr, None)



class Collector(threading.Thread):
  """Main collector thread that handles requests from central controller.
  """

  def __init__(self, conn, request):
    super(Collector,self).__init__()
    self.conn = conn
    self.request = request

  def run(self):
    reply = self.collect(self.request)
    try:
      utils.log("Sending reply to %s." % (str(self.conn.getpeername())))
      self.conn.sendall(utils.Encoder().encode(reply))
      self.conn.close()
    except:
      utils.log("Failed to send reply back.")
      traceback.print_exc(settings.LOG_FILE)


  def collect(self, request):
    """Collect data from clients.
    """
    result = CollectorResult(request)

    utils.log("Collecting neighbor APs...")
    result.neighbor_aps = AccessPoint.collect('wlan0') + AccessPoint.collect('wlan1')
    utils.log("%d neighbor APs found." % (len(result.neighbor_aps)))

    utils.log("Collecting associated clients...")
    result.clients = Station.collect('wlan0') + Station.collect('wlan1')
    utils.log("%d client stations found." % (len(result.clients)))

    if request['client_scan'] or request['client_traffic']:
      msg = json.dumps(request)
      utils.log("Sending messge: %s" % (msg))

      handler_threads = []
      for c in [c for c in result.clients if getattr(c, 'IP', None) is not None]:
        utils.log("Sending to %s (%s)" % (c.MAC, c.IP))
        try:
          conn = socket.create_connection((c.IP, settings.CLIENT_TCP_PORT), settings.CONNECTION_TIMEOUT_SEC*1000)
          conn.sendall(msg)
          t = HandlerThread(conn, c)
          t.start()
          handler_threads.append(t)
        except:
          utils.log("Failed to send to %s (%s)" % (c.MAC, c.IP))
          traceback.print_exc(settings.LOG_FILE)

      utils.log("Waiting for handler threads to finish.")
      for t in handler_threads:
        t.join()

    return result
