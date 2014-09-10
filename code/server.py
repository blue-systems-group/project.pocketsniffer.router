#!/usr/bin/python

import socket, json, traceback
import settings

from periodic import PeriodicTask

class ServerTask(PeriodicTask) :

  def __init__(self, client_task, gateway=settings.DEFAULT_GATEWAY,
               port=settings.DEFAULT_PORT, backlog=settings.DEFAULT_BACKLOG) :
    super(ServerTask, self).__init__(0)
    self.client_task = client_task
    self.gateway = gateway
    self.port = port
    self.backlog = backlog

  def recv_all(self, conn) :
    content = []
    conn.settimeout(30)
    try :
      while True :
        data = conn.recv(settings.DEFAULT_RECV_BUF)
        if len(data) == 0 :
          break
        content.append(data)
      return ''.join(content)
    except :
      self.log("Socket time out.")
      conn.close()
      return None


  def do_job(self) :
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((self.gateway, self.port))
    sock.listen(self.backlog)


    while True :
      try :
        self.log("Waiting for connection...")
        conn, addr = sock.accept()
        self.log("Got connection from " + '-'.join([str(i) for i in addr]))

        content = self.recv_all(conn)
        if content is None :
          continue

        self.log(content)
        msg = json.loads(content)
        self.client_task.update_rf(msg)
      except :
        self.log(traceback.format_exc())
        self.log("malformed msg: %s" % (content))

