import json
import sys
import re
import socket
import threading
import traceback

import utils
import settings
from common import Result, RequestHandler


class AccessPoint(object):
  """Scan result entry.

  Collected from the output of `iw wlan0 scan`.
  """

  IW_SCAN_PATTERNS = {
      'SSID': re.compile(r"""^SSID:\s(?P<SSID>.*)$""", re.MULTILINE),
      'BSSID': re.compile(r"""^BSS\s(?P<BSSID>[:\w]{17})\(on\swlan\d\)$""", re.MULTILINE),
      'frequency': re.compile(r"""^freq:\s(?P<frequency>\d{4})$""", re.MULTILINE),
      'level': re.compile(r"""^signal:\s(?P<level>[-\d]*?)\.00 dBm$""", re.MULTILINE),
      'clientNum': re.compile(r"""^\*\sstation\scount:\s(?P<clientNum>\d*)$""", re.MULTILINE),
      'utilization': re.compile(r"""^\*\schannel\sutili[sz]ation:\s(?P<utilization>\d*\/\d*)$""", re.MULTILINE),
      }


  def __init__(self):
    [setattr(self, attr, None) for attr in AccessPoint.IW_SCAN_PATTERNS.keys()]

  @classmethod
  def single_create(cls, lines):
    """Create one scan result entry."""
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
  results and traffic condition may also be available if clients provide such
  information.
  """


  IW_STATION_DUMP_PATTERNS = {
      'MAC': re.compile(r"""^Station\s(?P<MAC>[:\w]{17})\s\(on\swlan\d\)$""", re.MULTILINE),
      'inactiveTime': re.compile(r"""^inactive\stime:\s*(?P<inactiveTime>\d*)\sms$""", re.MULTILINE),
      'rxBytes': re.compile(r"""^rx\sbytes:\s*(?P<rxBytes>\d*)$""", re.MULTILINE),
      'rxPackets': re.compile(r"""^rx\spackets:\s*(?P<rxPackets>\d*)$""", re.MULTILINE),
      'txBytes': re.compile(r"""^tx\sbytes:\s*(?P<txBytes>\d*)$""", re.MULTILINE),
      'txPackets': re.compile(r"""^tx\spackets:\s*(?P<txPackets>\d*)$""", re.MULTILINE),
      'txRetries': re.compile(r"""^tx\sretries:\s*(?P<txRetries>\d*)$""", re.MULTILINE),
      'txFailed': re.compile(r"""^tx\sfailed:\s*(?P<txFailed>\d*)$""", re.MULTILINE),
      'signalAvg': re.compile(r"""^signal\savg:\s*(?P<signalAvg>-\d*).*$""", re.MULTILINE),
      'txBitrate': re.compile(r"""^tx\sbitrate:\s*(?P<txBitrate>[\d\.]*).*$""", re.MULTILINE),
      'rxBitrate': re.compile(r"""^rx\sbitrate:\s*(?P<rxBitrate>[\d\.]*).*$""", re.MULTILINE),
      }

  DHCP_LEASES_PATTERNS = re.compile(r"""^\d*\s(?P<MAC>[:\w]{17})\s(?P<IP>[\d\.]{7,15})\s(?P<hostname>[\w-]*?)\s.*$""", re.MULTILINE)

  def __init__(self):
    [setattr(self, attr, None) for attr in Station.IW_STATION_DUMP_PATTERNS.keys()]

  def set_scan_results(self, results):
    if results['detailed']:
      aps = AccessPoint.bulk_create(results['output'].split('\n'))
    else:
      aps = []
      for r in results['results']:
        ap = AccessPoint()
        for attr in ['SSID', 'BSSID', 'frequency', 'level']:
          setattr(ap, attr, r[attr])
        aps.append(ap)

    setattr(self, 'scanResult', aps)

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
  """ Handler thread for replies from clients."""

  def __init__(self, conn, clients):
    super(HandlerThread, self).__init__()
    self.conn = conn
    self.clients = clients

  def run(self):
    try:
      self.conn.settimeout(settings.READ_TIMEOUT_SEC)
      reply = json.loads(utils.recv_all(self.conn))
      self.conn.close()
    except:
      utils.log("Failed to decode client reply.")
      traceback.print_exc(settings.LOG_FILE)
      return

    client = self.clients[reply['mac']]

    utils.log("Got reply from %s (%s)" % (client.MAC, client.IP))
    try:
      if 'isPhoneLabPhone' in reply:
        setattr(client, 'isPhoneLabPhone', reply['isPhoneLabPhone'])
      else:
        setattr(client, 'isPhoneLabPhone', False)

      if 'scanResult' in reply:
        client.set_scan_results(reply['scanResult'])
      if 'traffic' in reply:
        client.set_traffic(reply['traffic'])
    except:
      utils.log("Failed to set scan results or traffic.")
      traceback.print_exc(settings.LOG_FILE)



class CollectorResult(Result):

  def __init__(self, request):
    super(CollectorResult, self).__init__(request)
    for attr in ['neighborAPs', 'clients']:
      setattr(self, attr, None)



class Collector(RequestHandler):
  """Main collector thread that handles requests from central controller."""

  def __init__(self, conn, request):
    super(Collector,self).__init__(conn, request)

  def handle(self, request):
    """Collect data from clients."""
    result = CollectorResult(request)

    utils.log("Collecting neighbor APs...")
    result.neighborAPs = AccessPoint.collect('wlan0') + AccessPoint.collect('wlan1')
    utils.log("%d neighbor APs found." % (len(result.neighborAPs)))

    utils.log("Collecting associated clients...")
    result.clients = Station.collect('wlan0') + Station.collect('wlan1')
    utils.log("%d client stations found." % (len(result.clients)))

    if request['clientScan'] or request['clientTraffic']:
      msg = json.dumps(request)
      utils.log("Sending messge: %s" % (msg))

      server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      server_sock.bind((settings.LOCAL_IP, settings.LOCAL_TCP_PORT))
      server_sock.listen(settings.LOCAL_BACKLOG)

      clients = []
      for c in [c for c in result.clients if getattr(c, 'IP', None) is not None]:
        utils.log("Sending to %s (%s)" % (c.MAC, c.IP))
        try:
          conn = socket.create_connection((c.IP, settings.CLIENT_TCP_PORT), settings.CONNECTION_TIMEOUT_SEC*1000)
          conn.sendall(msg)
          conn.close()
          clients.append(c)
        except:
          utils.log("Failed to send to %s (%s)" % (c.MAC, c.IP))
          traceback.print_exc(settings.LOG_FILE)

      clients = dict((c.MAC, c) for c in clients)

      utils.log("Waiting for response...")

      handler_threads = []
      for i in range(0, len(clients)):
        try:
          conn, addr = server_sock.accept()
        except KeyboardInterrupt:
          server_sock.close()
          sys.exit()

        t = HandlerThread(conn, clients)
        t.start()
        handler_threads.append(t)


      utils.log("Waiting for handler threads to finish.")
      for t in handler_threads:
        t.join()

    return result
