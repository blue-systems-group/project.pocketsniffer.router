from datetime import datetime as dt
import threading
import logging

import utils


logger = logging.getLogger('pocketsniffer')

class Result(object):

  def __init__(self, request):
    super(Result, self).__init__()
    self.created = dt.now()
    self.request = request


class RequestHandler(threading.Thread):

  def __init__(self, conn, request):
    super(RequestHandler, self).__init__()
    self.conn = conn
    self.request = request

  def run(self):
    reply = self.handle()
    if reply is None:
      return

    try:
      logger.debug("Sending reply to %s." % (str(self.conn.getpeername())))
      self.conn.sendall(utils.Encoder().encode(reply))
      self.conn.close()
    except:
      logger.exception("Failed to send reply back.")
