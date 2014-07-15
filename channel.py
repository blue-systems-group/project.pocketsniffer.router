import utils, settings, time
from periodic import PeriodicTask

"""
Periodic task that consider switching channel
"""
class ChannelSwitchTask(PeriodicTask) :

  def __init__(self, client_task, ap_task) :
    super(ChannelSwitchTask, self).__init__(settings.CHANNEL_SWITCH_INTERVAL_SEC)
    self.client_task = client_task
    self.ap_task = ap_task

  def do_job(self) :
    current_channel = utils.get_current_channel()
    self.log("Current channel: %d" % (current_channel))

    channel_vote = dict()

    now = time.time()

    with self.client_task.clients_lock :
      for c in self.client_task.clients.values() :
        if c.rf_last_updated is not None and now - c.rf_last_updated > settings.TRAFFIC_AGE_THRESHOLD :
          if c.channel_load is not None :
            c.channel_load = None
            self.log("Deleting old traffic info for %s" % (c.mac))
          continue

        load = c.channel_load
        if load is None or len(load) == 0 :
          self.log("No channel load info for " + str(c.mac))
          continue

        self.log("mac: %s, load: %s" % (c.mac, str(load)))

        candidate_channel = min(load, key=lambda t: load[t])
        if (current_channel not in load) or (load[current_channel] - load[candidate_channel] > settings.TRAFFIC_THRESHOLD) :
          channel_vote[candidate_channel] = channel_vote.get(candidate_channel, 0) + 1

    if len(channel_vote) == 0 :
      self.log("No votes, do not change channel.")
    else :
      self.log("Chanenl votes: " + str(channel_vote))
      choice = max(channel_vote, key = lambda t: channel_vote[t])
      if choice == current_channel :
        self.log("Current channel is optimal choice")
      else :
        self.log("Setting channel to %d" % (choice))
        utils.set_channel(choice)
