import time, thread
import utils

class PeriodicTask(object) :

  def __init__(self, interval) :
    self.interval = interval

  def do_job(self) :
    pass

  def job(self, dummy) :
    while True :
      try :
        self.do_job()
      except Exception as e:
        utils.log(str(e))

      time.sleep(self.interval)


  def get_lock(self) :
    return thread.allocate_lock()

  def start(self) :
    self.log("====== Starting " + self.__class__.__name__ + " ======")
    thread.start_new_thread(self.job, (None,))

  def log(self, msg) :
    utils.log("[%20s]: %s" % (self.__class__.__name__, msg))
