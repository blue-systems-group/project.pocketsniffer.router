import re
import threading
import BaseHTTPServer

import utils
import settings

FILE_SIZE_PATTERN = re.compile(r"""(?P<size>\d+)M""")
MB = 1024*1024

class ThroughputHandler(BaseHTTPServer.BaseHTTPRequestHandler):

  def do_GET(self):
    utils.log("HTTP GET %s" % (self.path))

    match = FILE_SIZE_PATTERN.search(self.path)
    if match is None:
      self.send_error(404, "Can not find size in file name.")
      return

    size = int(match.group('size'))
    utils.log("File size is %d MB." % (size))

    self.send_response(200)
    self.send_header('Content-type', 'application/octet-stream')
    self.send_header('Content-Length', str(size*MB))
    self.end_headers()

    for i in range(0, size):
      self.wfile.write('\x00'*MB)


class HttpServerThread(threading.Thread):

  def __init__(self, addr='', port=settings.HTTP_PORT):
    super(HttpServerThread, self).__init__()
    self.addr = addr
    self.port = port

  def run(self):
    utils.log("Starting HTTP server at port %d" % (self.port))
    httpd = BaseHTTPServer.HTTPServer((self.addr, self.port), ThroughputHandler)
    httpd.serve_forever()
