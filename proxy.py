#!/usr/bin/python
# -*- coding:utf-8 -*-
# modified from http://xiaoxia.org/2011/11/14/update-sogou-proxy-program-with-https-support/
try:
    #noinspection PyUnresolvedReferences
    import gevent, gevent.monkey

    gevent.monkey.patch_all()
except ImportError:
    pass

import httplib
import logging
import os
import random
import select
import socket
import struct
import sys
import threading
import time
import BaseHTTPServer
import ConfigParser
import SocketServer

import socks

X_SOGOU_AUTH = "9CD285F1E7ADB0BD403C22AD1D545F40/30/853edc6d49ba4e27"
SERVER_TYPES = [
    ("edu", 3),
    ("ctc", 3),
    ("cnc", 3),
    ("dxt", 3),
]
BUFFER_SIZE = 32768


# Minimize Memory Usage
threading.stack_size(128 * 1024)

def calc_sogou_hash(timestamp, host):
    s = (timestamp + host + "SogouExplorerProxy").encode("ascii")
    code = len(s)
    dwords = int(len(s) / 4)
    rest = len(s) % 4
    v = struct.unpack("%si%ss" % (str(dwords), str(rest)), s)
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
    return hex(code)[2:].rstrip("L").zfill(8)


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    remote = None
    sogou_host = None
    proxied = False

    # Ignore Connection Failure
    def handle(self):
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.handle(self)
        except (socks.ProxyError, socket.error):
            pass

    def finish(self):
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.finish(self)
        except (socks.ProxyError, socket.error):
            pass

    # CONNECT Data Transfer
    def remote_connect(self):
        if Handler.proxied:
            self.remote = socks.socksocket()
        else:
            self.remote = socket.socket()
        self.remote.settimeout(None)
        try:
            self.remote.connect((Handler.sogou_host, 80))
        except (socks.ProxyError, socket.error), e:
            return "%d: %s" % (e.errno, e.message)


    def add_sogou_header(self):
        self.headers["X-Sogou-Auth"] = X_SOGOU_AUTH
        self.headers["X-Sogou-Timestamp"] = hex(int(time.time()))[2:].rstrip("L").zfill(8)
        self.headers["X-Sogou-Tag"] = calc_sogou_hash(self.headers["X-Sogou-Timestamp"], self.headers["Host"])

    def remote_send_requestline(self):
        self.remote.sendall(self.requestline.encode("ascii") + b"\r\n")

    def remote_send_headers(self):
        self.remote.sendall(str(self.headers))
        self.remote.sendall("\r\n")

    def remote_send_postdata(self):
        if self.command == "POST":
            self.remote.sendall(self.rfile.read(int(self.headers["Content-Length"])))

    def local_write_connect(self):
        fdset = [self.remote, self.connection]
        while True:
            r, w, _ = select.select(fdset, [], [])
            if r:
                for soc in r:
                    i = fdset.index(soc)
                    try:
                        data = soc.recv(BUFFER_SIZE)
                    except (socks.ProxyError, socket.error), e:
                        self.send_error(httplib.BAD_GATEWAY, "%d: %s" % (e.errno, e.message))
                    else:
                        if not data:
                            return
                        the_other_soc = fdset[i ^ 1]
                        the_other_soc.sendall(data)

    def local_write_other(self):
        while True:
            response_data = self.http_response.read(BUFFER_SIZE)
            if not response_data:
                break
            self.wfile.write(response_data)

    def local_write_line(self):
        # Reply to the browser
        self.wfile.write("HTTP/1.1 {0:>s} {1:>s}\r\n{2:>s}\r\n".format(str(self.http_response.status),
            self.http_response.reason, "".join(self.http_response.msg.headers)))

    def build_local_response(self):
        self.http_response = httplib.HTTPResponse(self.remote, method=self.command)
        try:
            self.http_response.begin()
        except (socks.ProxyError, socket.error), e:
            logging.exception(e.message)

    def proxy(self):
        if self.command == "POST" and "Content-Length" not in self.headers:
            self.send_error(httplib.BAD_REQUEST, "POST method without Content-Length header!")
            return
        else:
            error_msg = self.remote_connect()
            if error_msg:
                self.send_error(httplib.BAD_GATEWAY, error_msg)
                return

        if 'Host' not in self.headers:
            self.send_error(httplib.BAD_REQUEST, "Host field missing in HTTP request headers.")
            return
        self.add_sogou_header()
        self.remote_send_requestline()
        self.remote_send_headers()
        self.remote_send_postdata()
        self.build_local_response()
        self.local_write_line()
        if self.command == "CONNECT":
            if self.http_response.status == httplib.OK:
                self.local_write_connect()
            else:
                self.send_error(httplib.BAD_GATEWAY,
                    "CONNECT method but response with status code %d" % self.http_response.status)
        else:
            self.local_write_other()

    def do_proxy(self):
        try:
            return self.proxy()
        except socket.timeout:
            self.send_error(httplib.GATEWAY_TIMEOUT)
        except (socks.ProxyError, socket.error):
            pass
        except Exception:
            logging.exception("Exception")

    do_HEAD = do_POST = do_GET = do_CONNECT = do_PUT = do_DELETE = do_OPTIONS = do_TRACE = do_proxy


class ThreadingHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    pass


def main():
    logging.basicConfig(level=logging.ERROR, format="%(asctime)-15s %(name)-8s %(levelname)-8s %(message)s",
        datefmt="%m-%d %H:%M:%S", stream=sys.stderr)

    config_file = ConfigParser.RawConfigParser()
    config_file.read("%s.ini" % os.path.splitext(__file__)[0])
    listen_ip = config_file.get("listen", "ip")
    listen_port = config_file.getint("listen", "port")
    server_type = SERVER_TYPES[config_file.getint("run", "type")]
    Handler.sogou_host = "h%d.%s.bj.ie.sogou.com" % (random.randint(0, server_type[1]), server_type[0])
    if config_file.getboolean("proxy", "enabled"):
        proxy_host = config_file.get("proxy", "host")
        proxy_port = config_file.getint("proxy", "port")
        proxy_type = getattr(socks, "PROXY_TYPE_" + config_file.get("proxy", "type").upper())
        socks.setdefaultproxy(proxy_type, proxy_host, proxy_port)
        Handler.proxied = False

    server = ThreadingHTTPServer((listen_ip, listen_port), Handler)

    print "Sogou Proxy\nRunning on %s\nListening on %s:%d" % (Handler.sogou_host, listen_ip, listen_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        exit()

if __name__ == "__main__":
    main()