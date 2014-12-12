import threading
import logging

import utils


logger = logging.getLogger('pocketsniffer')

class RequestHandler(threading.Thread):

  def __init__(self, conn, request):
    super(RequestHandler, self).__init__()
    self.conn = conn
    self.request = request
    self.reply = {'request': self.request}
    self.reply_lock = threading.Lock()

  def run(self):
    try:
      self.handle()
    except:
      logger.exception("Failed to handle request.")
      return

    try:
      logger.debug("Sending reply to %s." % (str(self.conn.getpeername())))
      self.conn.sendall(utils.Encoder().encode(self.reply))
      self.conn.close()
    except:
      logger.exception("Failed to send reply back.")
