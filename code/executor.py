import traceback

from common import Result, RequestHandler
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

    result.channel2 = utils.get_channel(False)
    result.channel5 = utils.get_channel(True)
    utils.log("Current channel: 2GHz %d, 5GHz %d." % (result.channel2, result.channel5))

    result.txPower2 = utils.get_txpower(False)
    result.txPower5 = utils.get_txpower(True)
    utils.log("Current txpower: 2GHz %d, 5GHz %d." % (result.txPower2, result.txPower5))

    return result
