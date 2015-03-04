import json
import time
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
from common import RequestHandler, Handler

logger = logging.getLogger('pocketsniffer')


IW_SCAN_PATTERNS = {
    'SSID': re.compile(r"""^SSID:\s?(?P<SSID>.{0,31})$""", re.MULTILINE),
    'BSSID': re.compile(r"""^BSS\s(?P<BSSID>[:\w]{17})\(on\swlan\d\)""", re.MULTILINE),
    'frequency': re.compile(r"""^freq:\s(?P<frequency>\d{4})$""", re.MULTILINE),
    'RSSI': re.compile(r"""^signal:\s(?P<RSSI>[-\d]*?)\.00 dBm$""", re.MULTILINE),
    'stationCount': re.compile(r"""^\*\sstation\scount:\s(?P<stationCount>\d*)$""", re.MULTILINE),
    'bssLoad': re.compile(r"""^\*\schannel\sutili[sz]ation:\s(?P<bssLoad>\d*\/\d*)$""", re.MULTILINE),
    }

IPERF_DURATION_PATTERN = re.compile(r"""-t\s+(?P<duration>\d+)""", re.VERBOSE)
IPERF_BW_PATTERN = re.compile(r"""(?P<bw>[\d\.]+)\sMbits/sec""", re.VERBOSE)



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

 
AP_COLLECT = ['apStatus', 'apScan', 'stationDump']
CLIENT_COLLECT = ['phonelabDevice', 'clientScan', 'clientTraffic', 'clientLatency', 'clientThroughput', 'nearbyDevices']

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


class IperfThread(threading.Thread):

  def __init__(self, port, udp, mac):
    super(IperfThread, self).__init__()
    self.bws = []
    self.mac = mac

  def run(self):
    logger.debug(self.cmd)
    proc = subprocess.Popen(self.cmd, shell=True, stdout=subprocess.PIPE)
    while proc.poll() is None:
      try:
        line = proc.stdout.readline()
        match = IPERF_BW_PATTERN.search(line)
        if match is not None:
          self.bws.append(float(match.group('bw')))
      except:
        logger.exception("Failed to read iperf output.")
        break


class IperfClientThread(IperfThread):

  def __init__(self, port, udp, mac, client_ip):
    super(IperfClientThread, self).__init__(port, udp, mac)
    self.cmd = 'iperf -c %s -t 20 -f m -i 1 -p %d' % (client_ip, port)
    if udp:
      self.cmd = '%s -u -b 72M' % (self.cmd)
    logger.debug("Starting iperf %s client on port %d with server %s" % ('UDP' if udp else 'TCP', port, client_ip))



class IperfServerThread(IperfThread):

  def __init__(self, port, udp, mac):
    super(IperfServerThread, self).__init__(port, udp, mac)
    logger.debug("Starting iperf %s server on port %d" % ('UDP' if udp else 'TCP', port))
    self.cmd = 'iperf -s -i 1 -p %d -f m' % (port)
    if udp:
      self.cmd = '%s -u' % (self.cmd)

  def run(self):
    logger.debug(self.cmd)
    proc = subprocess.Popen(self.cmd, shell=True, stdout=subprocess.PIPE)
    while proc.poll() is None:
      try:
        line = proc.stdout.readline()
        match = IPERF_BW_PATTERN.search(line)
        if match is not None:
          self.bws.append(float(match.group('bw')))
      except:
        logger.exception("Failed to read iperf output.")
        break


class CollectHandler(RequestHandler):
  """Main collector thread that handles requests from central controller."""

  def handle_client_reply(self, conn):
    try:
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

    logger.debug("Got client reply: %s" % (json.dumps(client_reply)))

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

      for key in CLIENT_COLLECT:
        if key in self.request:
          self.reply[key] = []

      if self.request.get('clientThroughput', False):
        iperfArgs = self.request['iperfArgs']
      else:
        iperfArgs = None

      if self.request.get('clientTraffic', False):
        block = False
      else:
        block = True

      iperf_threads = dict()

      target_clients = self.request.get('clients', [])

      station_dump = get_station_dump()
      stations = station_dump['band2g'] + station_dump['band5g']

      handler_threads = []

      for sta in stations:
        if 'IP' not in sta:
          logger.debug("Skip client %s with no IP." % (sta['MAC']))
          continue
        mac, ip = sta['MAC'], sta['IP']
        try:
          skip = False
          if self.request.get('clientTraffic', False) and mac in target_clients:
            skip = True

          if not self.request.get('clientTraffic', False) and len(target_clients) > 0 and mac not in target_clients:
            skip = True

          if skip:
            logger.debug("Skip client %s" % (mac))
            continue

          if self.request.get('clientThroughput', False):
            while True:
              port = random.randint(*settings.IPERF_PORT_RANGE)
              if port not in iperf_threads:
                break
            if '-s' in iperfArgs:
              t = IperfClientThread(port, '-u' in iperfArgs, mac, ip)
            else:
              t = IperfServerThread(port, '-u' in iperfArgs, mac)
              t.start()
            iperf_threads[port] = t
            self.request['iperfArgs'] = iperfArgs % (port)

          msg = json.dumps(self.request)
          logger.debug("Sending to %s (%s): %s " % (mac, ip, msg))
          conn = socket.create_connection((ip, settings.PUBLIC_TCP_PORT), settings.CONNECTION_TIMEOUT_SEC)
          conn.sendall(msg)
          conn.shutdown(socket.SHUT_WR)
          if block:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            t = threading.Thread(target=self.handle_client_reply, args=(conn,))
            t.start()
            handler_threads.append(t)
          else:
            conn.close()
        except:
          logger.exception("Failed to send request.")

      for t in iperf_threads.values():
        if isinstance(t, IperfClientThread):
          t.start()

      if len(handler_threads) > 0:
        logger.debug("Waiting for %d client replies." % (len(handler_threads)))
        for t in handler_threads:
          t.join()

      if len(iperf_threads) > 0:
        if isinstance(iperf_threads.values()[0], IperfServerThread):
          client_bw = dict((t.mac, t.bws) for t in iperf_threads.values())
          for entry in self.reply['clientThroughput']:
            mac = entry['MAC']
            if mac in client_bw:
              logger.debug("Updating bandwidths for %s: %s" % (mac, str(client_bw[mac])))
              entry['bandwidths'] = client_bw[mac]
              entry['overallBandwidth'] = client_bw[mac][-1]

        logger.debug("Killing iperf threads.")
        try:
          subprocess.check_call('pgrep -f "iperf" | xargs kill -9', shell=True)
        except:
          pass

    logger.debug("Finished handling collect request.")


class ReplyHandler(Handler):

  def __init__(self, reply):
    super(ReplyHandler, self).__init__()
    self.reply = reply


  def run(self):
    if 'clientScan' in self.reply and 'iwScanOutput' in self.reply['clientScan'][0]:
      self.reply['clientScan'][0]['resultList'] = parse_iw_scan(self.reply['clientScan'][0]['iwScanOutput'])
      del self.reply['clientScan'][0]['iwScanOutput']

    self.send_reply()
