import subprocess
import logging
import zlib
import time
import re
from json import JSONEncoder
from datetime import datetime as dt

import settings


logger = logging.getLogger('pocketsniffer')


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
  """Get current channel."""
  idx = 1 if is_5g else 0
  args = ['uci', 'show', 'wireless.radio%d.channel' % (idx)]
  output = subprocess.check_output(args)
  return int(output.split('=')[1])


IW_CHANNEL_PATTERN = re.compile(r"""channel\s(?P<channel>[\d]*)\s""", re.VERBOSE)

def set_channel(channel) :
  """Set current channel."""
  if channel not in settings.VALID_CHANNELS:
    raise Exception("Invalid channel %d" % (channel))

  idx = 0 if channel in settings.VALID_2GHZ_CHANNELS else 1

  # do not use the wifi command to switch channel, but still maintain the
  # channel coheraence of the configuration file
  args = ['uci', 'set', 'wireless.radio%d.channel=%d' % (idx, channel)]
  subprocess.check_call(args)
  subprocess.check_call(['uci', 'commit'])

  # this is the command that actually switches channel
  args = ['hostapd_cli', '-i', 'wlan%d' % (idx), 'chan_switch', '3', str(channel2freq(channel)), 'ht']
  subprocess.check_call(args)

  for unused in range(0, 3):
    time.sleep(1)
    output = subprocess.check_output('iw wlan%d info' % (idx), shell=True)
    match = IW_CHANNEL_PATTERN.search(output)
    if match is not None and int(match.group('channel')) == channel:
      break


def set_txpower(txpower_dbm, is_5g=False) :
  """Set transmission power."""
  idx = 0 if not is_5g else 1

  if not is_5g:
    if txpower_dbm not in settings.VALID_2GHZ_TXPOWER_DBM:
      raise Exception("Invalid txpowr (%d dBm) for " % (txpower_dbm))
  else:
    if txpower_dbm not in settings.VALID_5GHZ_TXPOWER_DBM:
      raise Exception("Invalid txpowr: %d" % (txpower_dbm))

  args = ['uci', 'set', 'wireless.radio%d.txpower=%d' % (idx, txpower_dbm)]
  subprocess.check_call(args)
  subprocess.check_call(['uci', 'commit'])

  args = ['iw', 'phy%d' % (idx), 'set', 'txpower', 'fixed', str(txpower_dbm*100)]
  subprocess.check_call(args)


def get_txpower(is_5g=False):
  idx = 0 if not is_5g else 1
  args = ['uci', 'show', 'wireless.radio%d.txpower' % (idx)]
  output = subprocess.check_output(args)
  return int(output.split('=')[1])


def scan(iface='wlan0'):
  args = ['iw', 'dev', iface, 'scan']
  return subprocess.check_output(args)


def station_dump(iface='wlan0'):
  args = ['iw', 'dev', iface, 'station', 'dump']
  return subprocess.check_output(args)


def recv_all(sock) :
  """Read as many as bytes from socket."""
  chunks = []
  sock.settimeout(settings.READ_TIMEOUT_SEC)
  try :
    while True :
      chunk = sock.recv(settings.BUF_SIZE)
      if len(chunk) == 0 :
        break
      chunks.append(chunk)
  except :
    pass

  data = ''.join(chunks)
  try:
    prev_size = len(data)
    data = zlib.decompress(data)
    after_size = len(data)
    logger.debug("Compressed msg: %d -> %d (%.2f%%)" % (after_size, prev_size, float(prev_size)/after_size*100))
  except zlib.error:
    pass
  
  return data


IP_PATTERN = re.compile(r"""inet\saddr:(?P<IP>[\d\.]{7,15})\s*""", re.VERBOSE)
def get_wan_ip():
  """Get WAN IP from ifconfig command output."""
  output = subprocess.check_output(['ifconfig', 'eth1'])
  match = IP_PATTERN.search(output)
  if match is not None:
    return match.group('IP')
  else:
    return None


HW_ADDR_PATTERN = re.compile(r"""HWaddr\s(?P<MAC>[\w:]{17})""", re.VERBOSE)
def get_iface_mac(iface):
  """ Get MAC address of iface. """
  output = subprocess.check_output(['ifconfig', iface])
  match = HW_ADDR_PATTERN.search(output)
  if match is not None:
    return match.group('MAC').lower()
  else:
    return None


def get_wan_mac():
  return get_iface_mac('eth1')





class Encoder(JSONEncoder):

  def __init__(self):
    super(Encoder, self).__init__()

  def default(self, o):
    if isinstance(o, dt):
      return o.isoformat()
    elif isinstance(o, float):
      return format(o, '.3f')
    return o.__dict__
