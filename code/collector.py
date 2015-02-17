import json
import re
import socket
import threading
import logging
import random
import subprocess
from datetime import datetime as dt

from jsonschema import validate

import utils
import settings
from common import RequestHandler

logger = logging.getLogger('pocketsniffer')


IW_SCAN_PATTERNS = {
    'SSID': re.compile(r"""^SSID:\s?(?P<SSID>.{0,31})$""", re.MULTILINE),
    'BSSID': re.compile(r"""^BSS\s(?P<BSSID>[:\w]{17})\(on\swlan\d\)""", re.MULTILINE),
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
      r['bssLoad'] = round(eval('1.0*%s' % (r['bssLoad'])), 3)
    if 'BSSID' in r:
      r['BSSID'] = r['BSSID'].lower()
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

  if 'BSSID' in info:
    info['BSSID'] = info['BSSID'].lower()
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

def get_ap_status():
  status = {'IP': utils.get_wan_ip(), 'MAC': utils.get_wan_mac(), 'timestamp': dt.now().isoformat(), 'band2g':{}, 'band5g':{}}
  for iface, band in [('wlan0', 'band2g'), ('wlan1', 'band5g')]:
    if iface not in subprocess.check_output('iwinfo', shell=True):
      status[band]['enabled'] = False
    else:
      status[band]['enabled'] = True
      status[band].update(parse_iwinfo(subprocess.check_output('iwinfo %s info' % (iface), shell=True)))
  return status


def get_ap_scan():
  ap_scan = []
  for iface in ['wlan0', 'wlan1']:
    try:
      scan_result = {'MAC': utils.get_iface_mac(iface), 'timestamp': dt.now().isoformat(), "detailed": True, 'resultList':[]}
      scan_result['resultList'] = parse_iw_scan(subprocess.check_output('iw %s scan' % (iface), shell=True))
      ap_scan.append(scan_result)
    except:
      logger.exception("Failed to get scan results for %s" % (iface))
  return ap_scan


def get_station_dump():
  station_dump = {'MAC': utils.get_wan_mac(), 'timestamp': dt.now().isoformat()}
  for iface, band in [('wlan0', 'band2g'), ('wlan1', 'band5g')]:
    try:
      station_dump[band] = parse_iw_station_dump(subprocess.check_output('iw %s station dump' % (iface), shell=True))
      ip_table = parse_dhcp_leases()
      for s in station_dump[band]:
        if s['MAC'] in ip_table:
          s['IP'] = ip_table[s['MAC']]
    except:
      logger.exception("Failed to get station dump for %s", iface)
      station_dump[band] = []
  return station_dump


def iperf_server_worker(port, udp):
  logger.debug("Starting iperf %s server on port %d" % ('UDP' if udp else 'TCP', port))
  cmd = 'iperf -s -i 1 -p %d -f m -P 1' % (port)
  if udp:
    cmd = '%s -u' % (cmd)

  logger.debug(cmd)
  subprocess.check_output(cmd, shell=True)



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
      del client_reply['clientScan'][0]['iwScanOutput']

    self.reply_lock.acquire()
    for key in CLIENT_COLLECT:
      if key in client_reply:
        self.reply[key].extend(client_reply[key])
    self.reply_lock.release()


  def custom_validate(self):
    for attr, detail in [('clientTraffic', 'clients'), ('clientLatency', 'pingArgs'), ('clientThroughput', 'iperfArgs')]:
      if self.request.get(attr, False):
        if detail not in self.request:
          raise Exception("No %s specified while collecting %s." % (detail, attr))


  def handle(self):
    if self.request.get('apStatus', False):
      self.reply['apStatus'] = get_ap_status()

    if self.request.get('apScan', False):
      self.reply['apScan'] = get_ap_scan()

    if self.request.get('stationDump', False):
      self.reply['stationDump'] = get_station_dump()


    if any([self.request.get(k, False) for k in CLIENT_COLLECT]):
      for key in [k for k in CLIENT_COLLECT if self.request.get(k, False)]:
        self.reply[key] = []

      if self.request.get('clientThroughput', False):
        iperfArgs = self.request['iperfArgs']
      else:
        iperfArgs = None
      iperf_servers = dict()

      target_clients = self.request.get('clients', [])

      server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      server_sock.bind((settings.LOCAL_IP, settings.LOCAL_TCP_PORT))
      server_sock.listen(settings.LOCAL_BACKLOG)
      server_sock.settimeout(settings.SERVER_TIMEOUT_SEC)

      station_dump = get_station_dump()

      stations = station_dump['band2g'] + station_dump['band5g']


      expected_reply_num = 0
      for sta in stations:
        mac, ip = sta['MAC'], sta['IP']
        try:
          if self.request.get('clientTraffic', False) and mac in target_clients:
            logger.debug("Skip client %s" % (mac))
            continue

          if len(target_clients) > 0 and mac not in target_clients:
            logger.debug("Skip client %s" % (mac))
            continue

          if self.request.get('clientThroughput', False):
            while True:
              port = random.randint(*settings.IPERF_PORT_RANGE)
              if port not in iperf_servers:
                break
            t = threading.Thread(target=iperf_server_worker, args=(port, '-u' in self.request['iperfArgs']))
            t.start()
            iperf_servers[port] = t
            self.request['iperfArgs'] = iperfArgs % (port)

          msg = json.dumps(self.request)
          logger.debug("Sending to %s (%s): %s " % (mac, ip, msg))
          conn = socket.create_connection((ip, settings.CLIENT_TCP_PORT), settings.CONNECTION_TIMEOUT_SEC*1000)
          conn.sendall(msg)
          conn.close()
          expected_reply_num = expected_reply_num + 1
        except:
          logger.exception("Failed to send request.")

      logger.debug("Waiting for %d response." % (expected_reply_num))

      handler_threads = []
      for i in range(0, expected_reply_num):
        try:
          conn, addr = server_sock.accept()
          logger.debug("Got reply from %s" % (str(addr)))
          t = threading.Thread(target=self.handle_client_reply, args=(conn,))
          t.start()
          handler_threads.append(t)
        except:
          logger.exception("Failed to accept.")


      logger.debug("Waiting for handler threads to finish.")
      for t in handler_threads:
        t.join()

      if self.request.get('clientThroughput', False):
        self.request['iperfArgs'] = iperfArgs
