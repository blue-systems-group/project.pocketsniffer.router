import json
import sys
import re
import socket
import threading
import traceback

import utils
import settings
from common import Result, RequestHandler


IW_SCAN_PATTERNS = {
    'SSID': re.compile(r"""^SSID:\s(?P<SSID>.*)$""", re.MULTILINE),
    'BSSID': re.compile(r"""^BSS\s(?P<BSSID>[:\w]{17})\(on\swlan\d\)$""", re.MULTILINE),
    'frequency': re.compile(r"""^freq:\s(?P<frequency>\d{4})$""", re.MULTILINE),
    'RSSI': re.compile(r"""^signal:\s(?P<RSSI>[-\d]*?)\.00 dBm$""", re.MULTILINE),
    'stationCount': re.compile(r"""^\*\sstation\scount:\s(?P<stationCount>\d*)$""", re.MULTILINE),
    'bssLoad': re.compile(r"""^\*\schannel\sutili[sz]ation:\s(?P<bssLoad>\d*\/\d*)$""", re.MULTILINE),
    }



def parse_iw_scan(output):
  """ Parse the output of `iw iface scan`, and return a list of scanResultEntry. """
  lines = output.split('\n')
  index = [i for i in xrange(0, len(lines)) if lines[i].startswith('BSS ')] + [len(lines)]
  results = []
  for i, j in zip(index[:-1], index[1:]):
    s = '\n'.join([l.strip() for l in lines[i:j]])
    r = dict()
    for name, pattern in IW_SCAN_PATTERNS.items():
      match = pattern.search(s)
      if match is not None:
        r[name] = match.group(name)
    for name in ['frequency', 'RSSI', 'stationCount']:
      r[name] = int(r[name])
    if 'bssLoad' in r:
      r['bssLoad'] = int(1000*eval('1.0*%s' % (r['bssLoad'])))/1000.0
    results.append(r)
  return results


IWINFO_PATTERNS = {
    'BSSID': re.compile(r"""Access\sPoint:\s(?P<BSSID>[:\w]{17})$""", re.MULTILINE),
    'SSID': re.compile(r"""ESSID:\s"(?P<SSID>.*)"$""", re.MULTILINE),
    'channel': re.compile(r"""Channel:\s(?P<channel>\d+)""", re.MULTILINE),
    'txPower': re.compile(r"""Tx-Power:\s(?P<txPower>\d+)""", re.MULTILINE),
    'signal': re.compile(r"""Signal:\s(?P<signal_dbm>[-\d]+)""", re.MULTILINE),
    'noise': re.compile(r"""Noise:\s(?P<noise_dbm>[-\d]+)""", re.MULTILINE),
    }


def parse_iwinfo(output):
  """ Parse the output of `iwinfo iface info`, return dict of information. """ 
  info = dict()
  for name, pattern in IWINFO_PATTERNS.items():
    match = pattern.search(output)
    if match is not None:
      info[name] = match.group(name)
  for name in ['channel', 'txPower', 'signal', 'noise']:
    info[name] = int(info[name])
  return info


IW_STATION_DUMP_PATTERNS = {
    'MAC': re.compile(r"""^Station\s(?P<MAC>[:\w]{17})\s\(on\swlan\d\)$""", re.MULTILINE),
    'inactiveTime': re.compile(r"""^inactive\stime:\s*(?P<inactiveTime>\d*)\sms$""", re.MULTILINE),
    'rxBytes': re.compile(r"""^rx\sbytes:\s*(?P<rxBytes>\d*)$""", re.MULTILINE),
    'rxPackets': re.compile(r"""^rx\spackets:\s*(?P<rxPackets>\d*)$""", re.MULTILINE),
    'txBytes': re.compile(r"""^tx\sbytes:\s*(?P<txBytes>\d*)$""", re.MULTILINE),
    'txPackets': re.compile(r"""^tx\spackets:\s*(?P<txPackets>\d*)$""", re.MULTILINE),
    'txFailures': re.compile(r"""^tx\sfailed:\s*(?P<txFailures>\d*)$""", re.MULTILINE),
    'txRetries': re.compile(r"""^tx\sretries:\s*(?P<txRetries>\d*)$""", re.MULTILINE),
    'avgSignal': re.compile(r"""^signal\savg:\s*(?P<avgSignal>-\d*).*$""", re.MULTILINE),
    'txBitrate': re.compile(r"""^tx\sbitrate:\s*(?P<txBitrate>[\d\.]*).*$""", re.MULTILINE),
    'rxBitrate': re.compile(r"""^rx\sbitrate:\s*(?P<rxBitrate>[\d\.]*).*$""", re.MULTILINE),
    }


def parse_iw_station_dump(output):
  """ Parse the output of `iw iface station dump`, return dict of information. """ 
  lines = output.split('\n')
  index = [i for i in xrange(0, len(lines)) if lines[i].startswith('Station ')] + [len(lines)]
  stations = []
  for i, j in zip(index[:-1], index[1:]):
    s = '\n'.join([l.strip() for l in lines[i:j]])
    t = dict()
    for name, pattern in IW_STATION_DUMP_PATTERNS.items():
      match = pattern.search(s)
      if match is not None:
        t[name] = match.group(name)
    for name in t.keys():
      if name != 'MAC':
        t[name] = int(t[name])
    stations.append(t)
  return stations


DHCP_LEASES_PATTERNS = re.compile(r"""^\d*\s(?P<MAC>[:\w]{17})\s(?P<IP>[\d\.]{7,15})\s(?P<hostname>[\w-]*?)\s.*$""", re.MULTILINE)
def parse_dhcp_leases():
  """ Parse /var/dhcp.leases, return MAC->IP mapping. """
  s = dict()
  with open('/var/dhcp.leases') as f :
    for line in f.readlines():
      match = DHCP_LEASES_PATTERNS.match(line)
      if match is not None:
        s[match.group['MAC']] = match.group('IP')
  return s

 



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



class CollectHandler(RequestHandler):
  """Main collector thread that handles requests from central controller."""

  def handle(self):
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
