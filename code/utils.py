import subprocess
import time
import re
from json import JSONEncoder
from datetime import datetime as dt

import settings


def channel2freq(channel) :
  if channel >=1 and channel <= 11 :
    return 2412 + (channel-1)*5
  elif channel >= 36 and channel <= 165 :
    return 5180 + (channel-36)*5
  else :
    raise Exception("Invalid channel %d" % (channel))


def freq2channel(freq) :
  if freq >= 2412 and freq <= 2462 :
    return (freq-2412)/5 + 1;
  elif freq >= 5180 and freq <= 5825 :
    return (freq-5180)/5 + 36;
  else :
    raise Exception("Invalid frequency %d" % (freq))


def get_channel(is_5g=False) :
  if is_5g:
    radio = 'radio1'
  else:
    radio = 'radio0'
  args = ['uci', 'show', 'wireless.%s.channel' % (radio)]
  output = subprocess.check_output(args)
  return int(output.split('=')[1])


def set_channel(channel) :
  if channel not in settings.VALID_CHANNELS:
    raise Exception("Invalid channel %d" % (channel))

  if channel <= 11:
    radio = 'radio0'
    iface = 'wlan0'
  else:
    radio = 'radio1'
    iface = 'wlan1'

  # do not use the wifi command to switch channel, but still maintain the
  # channel coheraence of the configuration file
  args = ['uci', 'set', 'wireless.%s.channel=%d' % (radio, channel)]
  subprocess.call(args)
  subprocess.call(['uci', 'commit'])

  # this is the command that actually switches channel
  args = ['hostapd_cli', '-i', iface, 'chan_switch', '1', str(channel2freq(channel)), 'ht']
  subprocess.call(args)


def set_txpower(txpower_dbm, is_5g=False) :
  if not is_5g:
    radio = 'radio0'
    phy = 'phy0'
    if txpower_dbm not in settings.VALID_TXPOWER_2GHZ:
      raise Exception("Invalid txpowr: %d" % (txpower_dbm))
  else:
    radio = 'radio1'
    phy = 'phy1'
    if txpower_dbm not in settings.VALID_TXPOWER_5GHZ:
      raise Exception("Invalid txpowr: %d" % (txpower_dbm))

  args = ['uci', 'set', 'wireless.%s.txpower=%d' % (radio, txpower_dbm)]
  subprocess.call(args)
  subprocess.call(['uci', 'commit'])

  args = ['iw', phy, 'set', 'txpower', 'fixed', str(txpower_dbm*100)]
  subprocess.call(args)


def get_txpower(is_5g=False):
  if is_5g:
    radio = 'radio1'
  else:
    radio = 'radio0'
  args = ['uci', 'show', 'wireless.%s.txpower' % (radio)]
  output = subprocess.check_output(args)
  return int(output.split('=')[1])


def log(str) :
  print >>settings.LOG_FILE, "[" + time.strftime('%c') + "] " + str

def scan(iface='wlan0'):
  args = ['iw', 'dev', iface, 'scan']
  return subprocess.check_output(args)


def station_dump(iface='wlan0'):
  args = ['iw', 'dev', iface, 'station', 'dump']
  return subprocess.check_output(args)


def get_station_info() :
  args = ['iw', 'wlan0', 'station', 'dump']
  output = subprocess.check_output(args)
  sta_num = output.count('Station')
  lines = output.split('\n')

  stations = dict()

  for i in xrange(0, sta_num) :
    base = i*18
    mac = lines[base+0].split()[1]
    info = dict()
    info['mac'] = mac
    info['rx_bytes'] = int(lines[base+2].split()[2])
    info['tx_bytes'] = int(lines[base+4].split()[2])
    info['signal'] = int(lines[base+8].split()[1])
    stations[mac] = info

  return stations

def get_dhcp_list() :
  client_list = dict()
  with open('/var/dhcp.leases') as f :
    for line in f.readlines() :
      parts = line.split()
      if len(parts) == 5 :
        client_list[parts[1]] = {"ip": parts[2], "hostname": parts[3]}

  return client_list


def recv_all(sock, buf_size=8192) :
  content = []
  sock.settimeout(30)
  try :
    while True :
      data = sock.recv(buf_size)
      if len(data) == 0 :
        break
      content.append(data)
  except :
    pass
  return ''.join(content)

def get_public_ip():
  IP_PATTERN = re.compile(r"""inet\saddr:(?P<IP>[\d\.]{7,15})\s*""", re.VERBOSE)
  output = subprocess.check_output(['ifconfig', 'eth1'])
  match = IP_PATTERN.search(output)
  if match is not None:
    return match.group('IP')
  return None



class Encoder(JSONEncoder):

  def __init__(self):
    super(Encoder, self).__init__()

  def default(self, o):
    if isinstance(o, dt):
      return o.isoformat()
    elif isinstance(o, float):
      return format(o, '.3f')
    return o.__dict__


