import socket
import json
import zlib

import settings
from periodic import PeriodicTask

class QueryTask(PeriodicTask) :

  def __init__(self, client_task, gateway=settings.DEFAULT_GATEWAY, port=settings.UDP_PORT) :
    super(QueryTask, self).__init__(settings.QUERY_INTERVAL_SEC)
    self.gateway = gateway
    self.port = port
    self.client_task = client_task

    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # self.sock.bind((self.gateway, self.port))
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

  def do_job(self) :

    with self.client_task.clients_lock :
      for mac, client in self.client_task.clients.items() :
        if client.ip is None :
          self.log("Ignoring %s: no IP." % (mac))
          continue
        
        msg = zlib.compress(json.write({"hello":"world"}), 9)
        self.log("Querying %s (%s). Msg: %s" % (mac, client.ip, ' '.join([c.encode('hex') for c in msg])))
        self.sock.sendto(msg, (client.ip, self.port))
