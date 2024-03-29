#!/usr/bin/python

import socket
import zlib
import json
import logging
import subprocess


from jsonschema import validate

import utils
import settings


from collector import CollectHandler, ReplyHandler
from executor import APConfigHandler, ClientExecuteHandler, JammingHandler
from heartbeat import HeartbeatThread

logger = logging.getLogger('pocketsniffer')

HANDLER_MAPPING = {
    'collect': CollectHandler,
    'apConfig': APConfigHandler,
    'clientReassoc': ClientExecuteHandler,
    'clientReboot': ClientExecuteHandler,
    'startJamming': JammingHandler,
    'stopJamming': JammingHandler,
    }



def main() :
  public_ip = utils.get_wan_ip()

  if public_ip is not None:
    logger.debug("Public IP is %s" % (public_ip))
  else:
    logger.error("Failed to get public IP.")
    return

  logger.debug("Cleanup iperf servers.")
  try:
    subprocess.check_call('pgrep -f "iperf" | xargs kill -9', shell=True)
  except:
    pass


  server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  server_sock.bind(('0.0.0.0', settings.PUBLIC_TCP_PORT))
  server_sock.listen(settings.PUBLIC_BACKLOG)

  logger.debug("Listening on %s (%d)..." % (public_ip, settings.PUBLIC_TCP_PORT))

  for t in [HeartbeatThread]:
    t().start()

  try:
    while True:
      conn, addr = server_sock.accept()

      data = utils.recv_all(conn)

      try:
        request = json.loads(data)
      except:
        logger.exception("Failed to read message.")
        continue

      if 'action' in request:
        schema = settings.REQUEST_SCHEMA
        handler_thread = HANDLER_MAPPING[request['action']](conn, request)
      elif 'request' in request:
        schema = settings.REPLY_SCHEMA
        handler_thread = ReplyHandler(request)
      else:
        logger.error("Not a request or reply.")
        continue

      try:
        validate(request, schema)
      except:
        logger.exception("Failed to validate request msg.")
        continue

      logger.debug("Got message from %s: %s" % (addr, json.dumps(request)))
      handler_thread.start()
  except:
    logger.exception("Failed to listen.")
    server_sock.close()

if __name__ == '__main__' :
  main()
