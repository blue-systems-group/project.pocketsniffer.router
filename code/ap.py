import json
import utils, settings
from periodic import PeriodicTask

"""
Access Point
Obtained by "iw scan"
"""

class AP(object) :

  def __init__(self) :
    self.ssid = None
    self.bssid = None
    self.channel = None
    self.signal = None
    self.station_count = None
    self.channel_utilization = None


  @classmethod
  def create(cls, lines) :
    ap = AP()
    for line in [l.strip() for l in lines] :
      parts = line.split()
      if line.endswith('(on wlan0)') :
        ap.bssid = parts[1][:-3]
      elif line.startswith('freq:') :
        ap.channel = utils.freq2channel(int(parts[1]))
      elif line.startswith('signal:') :
        ap.signal = int(float(parts[1]))
      elif line.startswith('SSID:') :
        ap.ssid = parts[1]
      elif line.startswith('* station count:') :
        ap.station_count = int(parts[3])
      elif line.startswith('* channel utilisation:') :
        ap.channel_utilization = int(parts[3].split('/')[0])

    return ap
  
  def __str__(self) :
    return str(self.__dict__)


"""
Periodic task that updates AP list
"""
class APTask(PeriodicTask) :

  def __init__(self) :
    super(APTask, self).__init__(settings.AP_SCAN_INTERVAL_SEC)
    self.aps = dict()
    self.aps_lock = self.get_lock()


  def do_job(self) :
    output = utils.scan().split('\n')
    index = [i for i in xrange(0, len(output)) if output[i].startswith('BSS')]
    index.append(len(output))
    aps = [AP.create(output[i:j]) for i, j in zip(index[:-1], index[1:])]

    with self.aps_lock :
      del self.aps
      self.aps = aps

    self.log("Updated AP list, %d APs found." % (len(self.aps)))
