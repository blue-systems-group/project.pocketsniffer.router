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


  def custom_validate(self):
    pass

  def run(self):
    self.custom_validate()

    try:
      self.handle()
    except:
      logger.exception("Failed to handle request.")
      return

    if self.reply is not None:
      logger.debug("Sending reply to %s." % (str(self.conn.getpeername())))
      try:
        self.conn.sendall(utils.Encoder().encode(self.reply))
      except:
        logger.exception("Failed to send reply back.")

    try:
      self.conn.close()
    except:
      pass
