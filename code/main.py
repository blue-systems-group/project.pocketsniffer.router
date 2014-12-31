#!/usr/bin/python

import socket
import json
import logging
import subprocess


from jsonschema import validate

import utils
import settings


from collector import CollectHandler
from executor import APConfigHandler, ClientReasocHandler
from heartbeat import HeartbeatThread

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

  logger.debug("Starting iperf daemon")

  try:
    subprocess.check_call('pgrep -f "iperf" | xargs kill -9', shell=True)
  except :
    logger.exception("Failed to kill existing iperf daemon")

  try:
    subprocess.check_call('iperf -s -p %d -D -i 1 > %s &' % (settings.IPERF_TCP_PORT, settings.IPERF_TCP_LOGGING_FILE), shell=True)
    subprocess.check_call('iperf -s -p %d -D -u -i 1 > %s &' % (settings.IPERF_UDP_PORT, settings.IPERF_UDP_LOGGING_FILE), shell=True)
  except:
    logger.exception("Failed to start iperf daemon")

  logger.debug("Successfully fired up iperf daemon.");

  logger.debug("Starting heartbeat thread.")
  heartbeat = HeartbeatThread()
  heartbeat.start()
  
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



if __name__ == '__main__' :
  main()
