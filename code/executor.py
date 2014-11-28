import traceback

from common import Result, RequestHandler
import utils
import settings


class ExecutorResult(Result):

  def __init__(self, request):
    super(ExecutorResult, self).__init__(request)
    for attr in ['channel_2g', 'channel_5g', 'txpower_2g', 'txpower_5g']:
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

    result.channel_2g = utils.get_channel(False)
    result.channel_5g = utils.get_channel(True)
    utils.log("Current channel: 2GHz %d, 5GHz %d." % (result.channel_2g, result.channel_5g))

    result.txpower_2g = utils.get_txpower(False)
    result.txpower_5g = utils.get_txpower(True)
    utils.log("Current txpower: 2GHz %d, 5GHz %d." % (result.txpower_2g, result.txpower_5g))

    return result
