#!/usr/bin/python

import socket, json, thread, time
import utils
import settings

from client import Client
from ap import AP

GATEWAY = '192.168.1.1'
PORT = 1688
BACKLOG = 32
RECV_BUF = 4*1024

g_clients = dict()
g_clients_lock = thread.allocate_lock()

g_aps = dict()
g_ap_lock = thread.allocate_lock()

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

  utils.log("Update client thread running")

  while True :
    with g_clients_lock :
      for mac, info in utils.get_clients().items() :
        if mac not in g_clients :
          g_clients[mac] = Client()

        g_clients[mac].update_info(info)

      now = time.time()
      for mac in g_clients.keys() :
        if now - g_clients[mac].last_updated > 3 * settings.STATION_DUMP_INTERVAL_SEC :
          utils.log("Deleting " + mac)
          del g_clients[mac]

    utils.log("Updated client list: %s" % (', '.join(g_clients.keys())))
    time.sleep(settings.STATION_DUMP_INTERVAL_SEC)

def update_ap_thread(dummy) :
  global g_aps, g_ap_lock

  while True :
    with g_ap_lock:
      g_aps = AP.update()

    utils.log("AP list updated, %d ap seen." % (len(g_aps)))
      
    time.sleep(settings.AP_SCAN_INTERVAL_SEC)


def channel_switch_thread(dummy) :
  global g_clients, g_clients_lock

  utils.log("Channel switch thread running")

  while True :
    current_channel = utils.get_channel()
    channel_vote = dict()

    utils.log("Current channel: %d" % (current_channel))

    with g_clients_lock :
      for c in g_clients.values() :
        load = c.channel_load
        if load is None or len(load) == 0 :
          utils.log("No channel load info for " + str(c.mac))
          continue

        utils.log("mac: %s, load: %s" % (c.mac, str(load)))

        candidate_channel = min(load, key=lambda t: load[t])
        if load[current_channel] - load[candidate_channel] > settings.TRAFFIC_THRESHOLD :
          channel_vote[candidate_channel] = channel_vote.get(candidate_channel, 0) + 1

    if len(channel_vote) != 0 :
      choice = max(channel_vote, key = lambda t: channel_vote[t])
      utils.log("final choice: %d" % (choice))
      if choice != utils.get_channel() :
        utils.set_channel(choice)
      else :
        utils.log("Current channel is optimal choice")
    else :
      utils.log("No votes, do not change channel.")

    time.sleep(settings.CHANNEL_SWITCH_INTERVAL_SEC)


def update_client(msg) :
  global g_clients, g_clients_lock

  mac = msg['MAC']
  with g_clients_lock :
    if mac not in g_clients :
      g_clients[mac] = Client()
      g_clients[mac].mac = mac

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
    try :
      msg = json.read(content)
      update_client(msg)
    except :
      utils.log("malformed msg: %s" % (content))
      raise


def main() :
  thread.start_new_thread(server_thread, (None,))
  thread.start_new_thread(update_client_thread, (None,))
  thread.start_new_thread(update_ap_thread, (None,))
  thread.start_new_thread(channel_switch_thread, (None,))

  while True :
    pass

if __name__ == '__main__' :
  main()
