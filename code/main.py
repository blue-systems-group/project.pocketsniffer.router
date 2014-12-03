#!/usr/bin/python

import socket
import json
import sys

import traceback

import utils
import settings

from collector import Collector
from executor import Executor
from throughput import HttpServerThread


def main() :
  httpd = HttpServerThread()
  httpd.start()

  public_ip = utils.get_public_ip()

  if public_ip is not None:
    utils.log("Collector created on IP %s" % (public_ip))
  else:
    utils.log("Failed to get public IP.")
    return

  server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  server_sock.bind((public_ip, settings.PUBLIC_TCP_PORT))
  server_sock.listen(settings.PUBLIC_BACKLOG)

  utils.log("Listening on %s (%d)..." % (public_ip, settings.PUBLIC_TCP_PORT))

  try:
    while True:
      conn, addr = server_sock.accept()
      try:
        request = json.loads(utils.recv_all(conn))
      except:
        utils.log("Failed to read message.")
        traceback.print_exc(settings.LOG_FILE)
        continue

      utils.log("Got message from %s: %s" % (addr, json.dumps(request)))

      if 'action' not in request:
        utils.log("No action specified. Ignoring...")
        continue

      if request['action'] == 'collect':
        utils.log("Starting collector thread.")
        Collector(conn, request).start()

      if request['action'] == 'execute':
        utils.log("Starting Exectutor thread.")
        Executor(conn, request).start()
  except KeyboardInterrupt:
    utils.log("Ctrl-C detected. Exiting.")
    utils.log("Closing server socket.")
    server_sock.close()
    utils.log("Shutting down HTTP server.")
    httpd.shutdown()


 

if __name__ == '__main__' :
  main()
