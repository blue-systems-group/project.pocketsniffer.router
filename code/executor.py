import traceback
import socket
import json

from common import Result, RequestHandler
from collector import Station
import utils
import settings


class ExecutorResult(Result):

  def __init__(self, request):
    super(ExecutorResult, self).__init__(request)
    for attr in ['channel2', 'channel5', 'txPower2', 'txPower5']:
      setattr(self, attr, None)


class Executor(RequestHandler):

  def __init__(self, conn, request):
    super(Executor, self).__init__(conn, request)


  def handle(self, request):
    result = ExecutorResult(request)

    if 'channel' in request:
      utils.log("Setting channel to %d." % (request['channel']))
      try:
        utils.set_channel(request['channel'])
      except:
        utils.log("Failed to set channel.")
        traceback.print_exc(settings.LOG_FILE)
        

    if 'txpower' in request:
      utils.log("Setting txpower to %d dBm." % (request['txpower']))
      try:
        utils.set_txpower(request['txpower'], request.get('is_5g', False))
      except:
        utils.log("Failed to set txpower.")
        traceback.print_exc(settings.LOG_FILE)

    if 'assoc' in request:
      utils.log("Making %s associate to %s" % (request['client'], request['assoc']))

      ip = None
      with open('/var/dhcp.leases') as f :
        for line in f.readlines():
          match = Station.DHCP_LEASES_PATTERNS.match(line)
          if match is not None and match.group('MAC') == request['client']:
            ip = match.group('IP')
            utils.log("Found client %s" % (ip))
            break

      if ip is None:
        utils.log("No client with MAC %s" % (request['client']))
      else:
        try:
          conn = socket.create_connection((ip, settings.CLIENT_TCP_PORT), settings.CONNECTION_TIMEOUT_SEC*1000)
          conn.sendall(json.dumps(request))
          conn.close()
        except:
          utils.log("Failed to send to %s (%s)" % (request['client'], ip))
          traceback.print_exc(settings.LOG_FILE)



    result.channel2 = utils.get_channel(False)
    result.channel5 = utils.get_channel(True)
    utils.log("Current channel: 2GHz %d, 5GHz %d." % (result.channel2, result.channel5))

    result.txPower2 = utils.get_txpower(False)
    result.txPower5 = utils.get_txpower(True)
    utils.log("Current txpower: 2GHz %d, 5GHz %d." % (result.txPower2, result.txPower5))

    return result
