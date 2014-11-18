import json
import re

import utils

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

  @classmethod
  def collect(cls, iface='wlan0'):
    output = utils.station_dump(iface).split('\n')
    index = [i for i in xrange(0, len(output)) if output[i].startswith('Station ')] + [len(output)]
    stas = [Station.create(output[i:j]) for i, j in zip(index[:-1], index[1:])]
    for sta in stas:
      setattr(sta, 'iface', iface)
    return stas
