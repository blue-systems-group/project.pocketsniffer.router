import threading
import json
import socket
import logging

import settings


logger = logging.getLogger('pocketsniffer')

class Handler(threading.Thread):

  def send_reply(self):
    logger.debug("Sending reply: %s" % (str(json.dumps(self.reply))))
    conn = socket.create_connection((settings.SERVER_NAME, settings.PUBLIC_TCP_PORT))
    conn.sendall(json.dumps(self.reply))
    conn.shutdown(socket.SHUT_WR)
    conn.close()
 

class RequestHandler(Handler):

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
    self.handle()
