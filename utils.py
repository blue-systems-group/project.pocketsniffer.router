import subprocess

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
