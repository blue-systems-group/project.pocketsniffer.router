#!/usr/bin/python

import socket
import json
import logging


from jsonschema import validate

import utils
import settings


from collector import CollectHandler
from executor import APConfigHandler, ClientReasocHandler
from throughput import HttpServerThread

logger = logging.getLogger('pocketsniffer')

HANDLER_MAPPING = {
    'collect': CollectHandler,
    'apConfig': APConfigHandler,
    'clientReassoc': ClientReasocHandler,
    }


def main() :
  public_ip = utils.get_wan_ip()

  if public_ip is not None:
    logger.debug("Public IP is %s" % (public_ip))
  else:
    logger.error("Failed to get public IP.")
    return

  
  httpd = HttpServerThread()
  httpd.start()
  logger.debug("HTTP server started.")

  server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  server_sock.bind((public_ip, settings.PUBLIC_TCP_PORT))
  server_sock.listen(settings.PUBLIC_BACKLOG)

  logger.debug("Listening on %s (%d)..." % (public_ip, settings.PUBLIC_TCP_PORT))

  try:
    while True:
      conn, addr = server_sock.accept()
      try:
        request = json.loads(utils.recv_all(conn))
      except:
        logger.exception("Failed to read message.")
        continue

      try:
        validate(request, settings.REQUEST_SCHEMA)
      except:
        logger.exception("Failed to validate request msg.")
        continue

      logger.debug("Got message from %s: %s" % (addr, json.dumps(request)))
      HANDLER_MAPPING[request['action']](conn, request).start()
  except:
    logger.exception("Failed to listen.")
    server_sock.close()
    httpd.shutdown()



if __name__ == '__main__' :
  main()
