import json
import re
import socket
import zlib

import utils

TCP_PORT = 6543
BUF_SIZE = 65536
LOCAL_IP = '192.168.1.1'

class AccessPoint(object):

  IW_SCAN_PATTERNS = {
      'SSID': re.compile(r"""^SSID:\s(?P<SSID>.*)$""", re.MULTILINE),
      'BSSID': re.compile(r"""^BSS\s(?P<BSSID>[:\w]{17})\(on\swlan\d\)$""", re.MULTILINE),
      'channel': re.compile(r"""^freq:\s(?P<channel>\d{4})$""", re.MULTILINE),
      'signal': re.compile(r"""^signal:\s(?P<signal>[-\d]*?)\.00 dBm$""", re.MULTILINE),
      'client_num': re.compile(r"""^\*\sstation\scount:\s(?P<client_num>\d*)$""", re.MULTILINE),
      'utilization': re.compile(r"""^\*\schannel\sutili[sz]ation:\s(?P<utilization>\d*\/\d*)$""", re.MULTILINE),
      }


  def __init__(self):
    for attr in AccessPoint.IW_SCAN_PATTERNS.keys():
      setattr(self, attr, None)

  @classmethod
  def create(cls, lines):
    ap = AccessPoint()
    output = '\n'.join([l.strip() for l in lines])
    for attr, pattern in cls.IW_SCAN_PATTERNS.items() :
      match = pattern.search(output)
      if match is not None:
        setattr(ap, attr, match.group(attr))
    return ap

  @classmethod
  def collect(cls, iface='wlan0'):
    output = utils.scan(iface).split('\n')
    index = [i for i in xrange(0, len(output)) if output[i].startswith('BSS ')] + [len(output)]
    aps = [AccessPoint.create(output[i:j]) for i, j in zip(index[:-1], index[1:])]
    for ap in aps:
      setattr(ap, 'iface', iface)
    return aps



class Station(object):

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
    for attr in Station.IW_STATION_DUMP_PATTERNS.keys():
      setattr(self, attr, None)


  @classmethod
  def create(cls, lines):
    sta = Station()
    output = '\n'.join([l.strip() for l in lines])
    for attr, pattern in cls.IW_STATION_DUMP_PATTERNS.items():
      match = pattern.search(output)
      if match is not None:
        setattr(sta, attr, match.group(attr))

    return sta

  def set_scan_results(self, iw_scan_output):
    pass


  @classmethod
  def collect(cls, iface='wlan0'):
    output = utils.station_dump(iface).split('\n')
    index = [i for i in xrange(0, len(output)) if output[i].startswith('Station ')] + [len(output)]
    stas = dict((sta.MAC, sta) for sta in [Station.create(output[i:j]) for i, j in zip(index[:-1], index[1:])])

    for sta in stas.values():
      setattr(sta, 'iface', iface)

    with open('/var/dhcp.leases') as f :
      for line in f.readlines():
        match = Station.DHCP_LEASES_PATTERNS.match(line)
        if match is not None and match.group('MAC') in stas:
          for attr in ['hostname', 'IP']:
            setattr(stas[match.group('MAC')], attr, match.group(attr))

    return stas.values()


def recv_all(sock) :
  content = []
  sock.settimeout(30)
  try :
    while True :
      data = sock.recv(BUF_SIZE)
      if len(data) == 0 :
        break
      content.append(data)
  except :
    pass
  return ''.join(content)



def collect(client_scan=False, client_traffic=False):
  result = dict()

  result['neighbor_aps'] = AccessPoint.collect('wlan0') + AccessPoint.collect('wlan1')
  result['associated_clients'] = Station.collect('wlan0') + Station.collect('wlan1')

  if client_scan or client_traffic:
    request = zlib.compress(json.dumps({'collectScanResult': client_scan, 'collectTraffic': client_traffic}))

    for client in result['associated_clients']:
      if client.IP is None:
        continue
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.connect(client.IP, TCP_PORT)
      sock.send(request)
      if not client_traffic:
        reply = json.loads(recv_all(sock))
        client.set_scan_results(reply['scanresult']['output'])
      sock.close()

    if client_traffic:
      sock = sock.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      sock.bind((LOCAL_IP, TCP_PORT))

      for i in range(0, len(result['associated_clients'])):
        conn, addr = sock.accept()
        reply = json.loads(recv_all(conn))
        client.set_scan_results(reply['scanresult']['output'])
        client.set_traffic(reply['traffic'])

  return result
