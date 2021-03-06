#! -*- coding:utf-8 -*-
#!/usr/bin/python
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import commands

def get_quic(path):
  return commands.getoutput('./client 127.0.0.1 4433 ' + path)

class MyHandler(BaseHTTPRequestHandler):
  def do_GET(self):
    try:
      res = get_quic(self.path).split('\r\n')
      self.send_response(int(res[0].split()[1]))
      self.send_header('Content-type','text/html; charset=utf-8')
      for line in res[1:-2] :
        self.send_header(line.split(': ')[0], line.split(': ')[1])
      self.end_headers()

      self.wfile.write(res[-1])
    except IOError:
      self.send_error(404, 'file not found: %s' % self.path)

def main():
  try:
    server = HTTPServer(('0.0.0.0', 8080), MyHandler)
    print'welcome to the server'  
    server.serve_forever()
  except KeyboardInterrupt:
    server.socket.close()

if  __name__=='__main__':
  main()
