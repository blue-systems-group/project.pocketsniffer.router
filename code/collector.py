import json
import sys
import re
import socket
import threading
import traceback
import logging
import subprocess
from datetime import datetime as dt

from jsonschema import validate

import utils
import settings
from common import RequestHandler

logger = logging.getLogger('pocketsniffer')


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
      if name in r:
        r[name] = int(r[name])
    if 'bssLoad' in r:
      r['bssLoad'] = float('%.3f' % eval('1.0*%s' % (r['bssLoad'])))
    results.append(r)
  return results


IWINFO_PATTERNS = {
    'BSSID': re.compile(r"""Access\sPoint:\s(?P<BSSID>[:\w]{17})$""", re.MULTILINE),
    'SSID': re.compile(r"""ESSID:\s"(?P<SSID>.*)"$""", re.MULTILINE),
    'channel': re.compile(r"""Channel:\s(?P<channel>\d+)""", re.MULTILINE),
    'txPower': re.compile(r"""Tx-Power:\s(?P<txPower>\d+)""", re.MULTILINE),
    'signal': re.compile(r"""Signal:\s(?P<signal>[-\d]+)""", re.MULTILINE),
    'noise': re.compile(r"""Noise:\s(?P<noise>[-\d]+)""", re.MULTILINE),
    }


def parse_iwinfo(output):
  """ Parse the output of `iwinfo iface info`, return dict of information. """ 
  info = dict()
  for name, pattern in IWINFO_PATTERNS.items():
    match = pattern.search(output)
    if match is not None:
      info[name] = match.group(name)
  for name in ['channel', 'txPower', 'signal', 'noise']:
    if name in info:
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
        t[name] = int(float(t[name]))
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
        s[match.group('MAC')] = match.group('IP')
  return s

 
CLIENT_COLLECT = ['phonelabDevice', 'clientScan', 'clientTraffic', 'clientLatency', 'clientThroughput']

class CollectHandler(RequestHandler):
  """Main collector thread that handles requests from central controller."""

  def handle_client_reply(self, conn):
    try:
      conn.settimeout(settings.READ_TIMEOUT_SEC)
      client_reply = json.loads(utils.recv_all(conn))
      conn.close()
    except:
      logger.exception("Failed to decode client reply.")
      return

    try:
      validate(client_reply, settings.REPLY_SCHEMA)
    except:
      logger.exception("Failed to validate client reply.")
      return

    if 'clientScan' in client_reply and 'iwScanOutput' in client_reply['clientScan'][0]:
      client_reply['clientScan'][0]['resultList'] = parse_iw_scan(client_reply['clientScan'][0]['iwScanOutput'])
      client_reply['clientScan'][0]['iwScanOutput'] = None

    self.reply_lock.acquire()
    for key in CLIENT_COLLECT:
      if key in client_reply:
        self.reply[key].extend(client_reply[key])
    self.reply_lock.release()


  def handle(self):
    """Collect data from clients."""

    if 'apStatus' in self.request and self.request['apStatus']:
      status = {'IP': utils.get_wan_ip(), 'MAC': utils.get_wan_mac(), 'band2g':{}, 'band5g':{}}
      for iface, band in [('wlan0', 'band2g'), ('wlan1', 'band5g')]:
        if iface not in subprocess.check_output('iwinfo', shell=True):
          status[band]['enabled'] = False
        else:
          status[band]['enabled'] = True
          status[band].update(parse_iwinfo(subprocess.check_output('iwinfo %s info' % (iface), shell=True)))
      self.reply['apStatus'] = status

    if 'apScan' in self.request and self.request['apScan']:
      scan_result = {'MAC': utils.get_wan_mac(), 'timestamp': dt.now().isoformat(), "detailed": True,\
          'resultList': parse_iw_scan(subprocess.check_output('iw wlan0 scan', shell=True))\
          + parse_iw_scan(subprocess.check_output('iw wlan1 scan', shell=True))}
      self.reply['apScan'] = scan_result

    if 'stationDump' in self.request and self.request['stationDump']:
      station_dump = {'MAC': utils.get_wan_mac(), 'timestamp': dt.now().isoformat()}
      for iface, band in [('wlan0', 'band2g'), ('wlan1', 'band5g')]:
        station_dump[band] = parse_iw_station_dump(subprocess.check_output('iw %s station dump' % (iface), shell=True))
        ip_table = parse_dhcp_leases()
        for s in station_dump[band]:
          s['IP'] = ip_table[s['MAC']]
      self.reply['stationDump'] = station_dump

    if any([k in self.request and self.request[k] for k in CLIENT_COLLECT]):

      for key in [k for k in CLIENT_COLLECT if k in self.request and self.request[k]]:
        self.reply[key] = []

      msg = json.dumps(self.request)
      logger.debug("Sending messge: %s" % (msg))

      server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      server_sock.bind((settings.LOCAL_IP, settings.LOCAL_TCP_PORT))
      server_sock.listen(settings.LOCAL_BACKLOG)

      stations = parse_dhcp_leases()

      expected_reply_num = 0
      for mac, ip in stations.items():
        try:
          logger.debug("Sending to %s (%s)" % (mac, ip))
          conn = socket.create_connection((ip, settings.CLIENT_TCP_PORT), settings.CONNECTION_TIMEOUT_SEC*1000)
          conn.sendall(msg)
          conn.close()
          expected_reply_num = expected_reply_num + 1
        except:
          logger.exception("Failed to send request.")

      logger.debug("Waiting for response...")

      handler_threads = []
      for i in range(0, expected_reply_num):
        try:
          conn, addr = server_sock.accept()
        except:
          logger.exception("Failed to accept.")

        t = threading.Thread(target=self.handle_client_reply, args=(conn,))
        t.start()
        handler_threads.append(t)

      logger.debug("Waiting for handler threads to finish.")
      for t in handler_threads:
        t.join()
