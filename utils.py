import subprocess, time, re

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


def set_channel(channel) :
  args = ['uci', 'set']

  if channel <= 11 :
    args.append('wireless.radio0.channel=' + str(channel))
  else :
    args.append('wireless.radio1.channel=' + str(channel))

  subprocess.call(args)
  subprocess.call(['uci', 'commit'])
  subprocess.call(['wifi', 'reload'])

def set_txpower(txpower, is_5g=False) :
  args = ['uci', 'set']

  if is_5g is True :
    args.append('wireless.radio1.txpower=' + str(txpower))
  else :
    args.append('wireless.radio0.txpower=' + str(txpower))

  subprocess.call(args)
  subprocess.call(['uci', 'commit'])
  subprocess.call(['wifi', 'reload'])


def log(str) :
  print("[" + time.strftime('%c') + "] " + str)

def get_clients() :
  args = ['iw', 'wlan0', 'station', 'dump']
  output = subprocess.check_output(args)
  sta_num = output.count('Station')
  lines = output.split('\n')

  clients = dict()

  for i in xrange(0, sta_num) :
    base = i*18
    mac = lines[base+0].split()[1]
    info = dict()
    info['rx_bytes'] = int(lines[base+2].split()[2])
    info['tx_bytes'] = int(lines[base+4].split()[2])
    info['signal'] = int(lines[base+8].split()[1])
    clients[mac] = info

  return clients