#!/usr/bin/python

import time


from client import ClientTask
from ap import APTask
from server import ServerTask
from channel import ChannelSwitchTask

def main() :
  client_task = ClientTask()
  ap_task = APTask()
  server_task = ServerTask(client_task)
  channel_switch_task = ChannelSwitchTask(client_task, ap_task)

  client_task.start()
  ap_task.start()
  server_task.start()
  channel_switch_task.start()

  while True :
    time.sleep(100000)

if __name__ == '__main__' :
  main()
