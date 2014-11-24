import os, subprocess, time, re

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

def get_current_channel() :
  args = ['uci', 'show', 'wireless.radio0.channel']
  output = subprocess.check_output(args)
  return int(output.split('=')[1])

def set_channel(channel) :

  if channel <= 0 :
    log("Invalid channel %d" % (channel))
    return

  # do not use the wifi command to switch channel, but still maintain the
  # channel coheraence of the configuration file

  args = ['uci', 'set']

  if channel <= 11 :
    args.append('wireless.radio0.channel=' + str(channel))
  else :
    args.append('wireless.radio1.channel=' + str(channel))

  subprocess.call(args)
  subprocess.call(['uci', 'commit'])

  # this is the command that actually switches channel

  with open(os.devnull, 'wb') as f :
    cmd = 'chan_switch 1 ' + str(channel2freq(channel)) + '\n'
    p = subprocess.Popen('hostapd_cli', stdin=subprocess.PIPE, stdout=f, stderr=f)
    p.stdin.write(cmd)
    time.sleep(3)
    p.kill()

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


