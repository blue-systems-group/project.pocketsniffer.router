from datetime import datetime as dt

class Result(object):

  def __init__(self, request):
    super(Result, self).__init__()
    self.created = dt.now()
    self.request = request
