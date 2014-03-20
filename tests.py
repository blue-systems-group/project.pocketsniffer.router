
import time
import utils

def test_throughput(repeat=5, interval=10) :
  channels = [1, 6, 11]
  for i in range(0, repeat) :
    for chan in channels :
      print("setting channel to " + str(chan))
      utils.set_channel(chan)
      time.sleep(interval)
