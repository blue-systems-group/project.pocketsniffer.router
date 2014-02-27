#!/usr/bin/python

import socket, json, thread, time
import utils

from client import Client

GATEWAY = '192.168.1.1'
PORT = 1688
BACKLOG = 32
RECV_BUF = 4*1024

g_clients = dict()
g_clients_lock = thread.allocate_lock()

def recv_all(conn) :
  content = []
  while True :
    data = conn.recv(RECV_BUF)
    if len(data) == 0 :
      break
    content.append(data)

  return ''.join(content)

def update_client_thread(dummy) :
  global g_clients, g_clients_lock

  while True :
    new_clients = dict()
    with g_clients_lock :
      new_clients_list = utils.get_clients()
      utils.log(', '.join(new_clients_list.keys()))
      for mac, info  in new_clients_list :
        if mac in g_clients :
          g_clients[mac].update_info(info)
          new_clients[mac] = g_clients[mac]
        else :
          new_clients[mac] = Client.create(mac, info)

    g_clients = new_clients
    utils.log("Updated client list: %s" % (', '.join(g_clients.keys())))
    time.sleep(10)


def update_client(msg) :
  global g_clients, g_clients_lock
  mac = msg['MAC']
  with g_clients_lock :
    if mac not in g_clients :
      utils.log("Not a client: " + mac)
      return

    g_clients[mac].update_rf(msg)

def server_thread(dummy) :

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind((GATEWAY, PORT))
  sock.listen(BACKLOG)

  utils.log("Server thread running")

  while True :
    conn, addr = sock.accept()
    utils.log("Got connection from " + '-'.join([str(i) for i in addr]))

    content = recv_all(conn)
    utils.log(content)
    try :
      msg = json.read(content)
      update_client(msg)
    except :
      utils.log("malformed msg: %s" % (content))
      pass


def main() :
  thread.start_new_thread(server_thread, (None,))
  thread.start_new_thread(update_client_thread, (None,))

  while True :
    pass

if __name__ == '__main__' :
  main()
