#! -*- coding:utf-8 -*-
#!/usr/bin/python
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import ssl


class MyHandler(BaseHTTPRequestHandler):
  def do_GET(self):
    try:
      f=open(self.path[1:], 'r')
      self.send_response(200)
      self.send_header('Content-type', 'text/html')
      self.send_header('Content-type','text/html; charset=utf-8')
      self.end_headers()
      self.wfile.write(f.read())
      f.close()
    except IOError:
      self.send_error(404, 'file not found: %s' % self.path)

def main():
  try:
    server = HTTPServer(('0.0.0.0',8082), MyHandler)
    server.socket = ssl.wrap_socket(server.socket, certfile='server.pem', server_side=True)
    print'welcome to the server'  
    server.serve_forever()
  except KeyboardInterrupt:
    server.socket.close()

if  __name__=='__main__':
  main()
