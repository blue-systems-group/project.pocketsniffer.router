#!/usr/bin/python

import socket, json, thread, inspect, time, subprocess

GATEWAY = '192.168.1.1'
PORT = 1688
BACKLOG = 32
RECV_BUF = 32*1024

clients = dict()
stations = dict()
aps = dict()

clients_5g = dict()
stations_5g = dict()
aps_5g = dict()


def info_thread(dummy) :

  while True :
    pass


def server_thread(dummy) :
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind((GATEWAY, PORT))
  sock.listen(BACKLOG)

  print "Server thread running"

  while True :
    conn, addr = sock.accept()
    try :
      msg = json.read(conn.recv(RECV_BUF))

      if 'frequency' not in msg :
        print("msg doesn't contain frequency info, ignoring")
        continue

      print("Recv msg from %s(%s), on frequency %s, with %d scan results" % (addr, msg['MAC'], msg['frequency'], len(msg['results'])))

      if int(msg['frequency']) < 5000 :
        clients[msg['MAC']] = msg['results']
      else :
        clients_5g[msg['MAC']] = msg['results']
    except :
      pass


def main() :
  server = thread.start_new_thread(server_thread, (None,))

  while True :
    pass



if __name__ == '__main__' :
  main()
