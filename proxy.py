#!/usr/bin/python
# -*- coding:utf-8 -*-
# modified from http://xiaoxia.org/2011/11/14/update-sogou-proxy-program-with-https-support/

import errno
import httplib
import logging
import os
import random
import select
import socket
import struct
import threading
import time
import BaseHTTPServer
import ConfigParser
import SocketServer


X_SOGOU_AUTH = '9CD285F1E7ADB0BD403C22AD1D545F40/30/853edc6d49ba4e27'
SERVER_TYPES = [
    ('edu', 5),
    ('ctc', 3),
    ('cnc', 3),
]
BUFFER_SIZE = 32768


# Minimize Memory Usage
threading.stack_size(128 * 1024)

def calc_sogou_hash(timestamp, host):
    s = (timestamp + host + 'SogouExplorerProxy').encode('ascii')
    code = len(s)
    dwords = int(len(s) / 4)
    rest = len(s) % 4
    v = struct.unpack(str(dwords) + 'i' + str(rest) + 's', s)
    for vv in v:
        if type(vv) is str:
            break
        a = (vv & 0xFFFF)
        b = (vv >> 16)
        code += a
        code ^= ((code << 5) ^ b) << 0xb
        # To avoid overflows
        code &= 0xffffffff
        code += code >> 0xb
    if rest == 3:
        code += ord(s[len(s) - 2]) * 256 + ord(s[len(s) - 3])
        code ^= (code ^ (ord(s[len(s) - 1]) * 4)) << 0x10
        code &= 0xffffffff
        code += code >> 0xb
    elif rest == 2:
        code += ord(s[len(s) - 1]) * 256 + ord(s[len(s) - 2])
        code ^= code << 0xb
        code &= 0xffffffff
        code += code >> 0x11
    elif rest == 1:
        code += ord(s[len(s) - 1])
        code ^= code << 0xa
        code &= 0xffffffff
        code += code >> 0x1
    code ^= code * 8
    code &= 0xffffffff
    code += code >> 5
    code ^= code << 4
    code &= 0xffffffff
    code += code >> 0x11
    code ^= code << 0x19
    code &= 0xffffffff
    code += code >> 6
    code &= 0xffffffff
    return hex(code)[2:].rstrip('L').zfill(8)


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    remote = None
    proxy_host = None
    proxy_port = None

    # Ignore Connection Failure
    def handle(self):
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.handle(self)
        except socket.error:
            pass

    def finish(self):
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.finish(self)
        except socket.error:
            pass

    # CONNECT Data Transfer
    def transfer(self, a, b):
        fdset = [a, b]
        while True:
            r, w, e = select.select(fdset, [], [])
            if a in r:
                data = a.recv(BUFFER_SIZE)
                if not data:
                    break
                b.sendall(data)
            if b in r:
                data = b.recv(BUFFER_SIZE)
                if not data:
                    break
                a.sendall(data)

    def proxy(self):
        if self.remote is None:
            self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.remote.settimeout(None)
            self.remote.connect((Handler.proxy_host, Handler.proxy_port))
        self.remote.sendall(self.requestline.encode('ascii') + b"\r\n")
        # Add Sogou Verification Tags
        self.headers["X-Sogou-Auth"] = X_SOGOU_AUTH
        self.headers["X-Sogou-Timestamp"] = hex(int(time.time()))[2:].rstrip('L').zfill(8)
        self.headers["X-Sogou-Tag"] = calc_sogou_hash(self.headers["X-Sogou-Timestamp"], self.headers['Host'])
        self.remote.sendall(str(self.headers))
        self.remote.sendall('\r\n')
        # Send Post data
        if self.command == 'POST':
            if 'Content-Length' in self.headers:
                self.remote.sendall(self.rfile.read(int(self.headers['Content-Length'])))
            else:
                self.send_error(httplib.BAD_REQUEST, 'POST method without Content-Length header!')
                return
        response = httplib.HTTPResponse(self.remote, method=self.command)
        response.begin()

        # Reply to the browser
        self.wfile.write("HTTP/1.1 %s %s\r\n" % (str(response.status), response.reason))
        self.wfile.write("".join(response.msg.headers))
        self.wfile.write('\r\n')

        if self.command == "CONNECT" and response.status == httplib.OK:
            return self.transfer(self.remote, self.connection)
        else:
            while True:
                response_data = response.read(BUFFER_SIZE)
                if not response_data:
                    break
                self.wfile.write(response_data)

    def do_proxy(self):
        try:
            return self.proxy()
        except socket.timeout:
            self.send_error(httplib.GATEWAY_TIMEOUT)
        except socket.error, e:
            if e.errno == errno.ECONNABORTED:
                pass
            else:
                raise e
        except Exception:
            logging.exception("Exception")

    do_HEAD = do_POST = do_GET = do_CONNECT = do_proxy


class ThreadingHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    pass


def main():
    config_file = ConfigParser.RawConfigParser()
    config_file.read(os.path.splitext(__file__)[0] + '.ini')
    listen_ip = config_file.get('listen', 'ip')
    listen_port = config_file.getint('listen', 'port')
    server_type = SERVER_TYPES[config_file.getint('run', 'type')]
    Handler.proxy_host = 'h%d.%s.bj.ie.sogou.com' % (random.randint(0, server_type[1]), server_type[0])
    Handler.proxy_port = 80

    server = ThreadingHTTPServer((listen_ip, listen_port), Handler)

    print 'Sogou Proxy\nRunning on %s\nListening on %s:%d' % (Handler.proxy_host, listen_ip, listen_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        exit()

if __name__ == '__main__':
    main()