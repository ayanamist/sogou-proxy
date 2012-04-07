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
import sys
import threading
import time
import BaseHTTPServer
import ConfigParser
import SocketServer


X_SOGOU_AUTH = "9CD285F1E7ADB0BD403C22AD1D545F40/30/853edc6d49ba4e27"
SERVER_TYPES = [
    ("edu", 5),
    ("ctc", 3),
    ("cnc", 3),
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


class ProxyInfo(object):
    host = None
    ip = None
    port = 80


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    remote = None

    # Ignore Connection Failure
    def handle(self):
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.handle(self)
        except socket.error, e:
            if e.errno == errno.ECONNABORTED:
                pass
            else:
                logging.exception("")

    def finish(self):
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.finish(self)
        except socket.error, e:
            if e.errno == errno.ECONNABORTED:
                pass
            else:
                logging.exception("")

    # CONNECT Data Transfer
    def remote_connect(self):
        self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.remote.settimeout(None)
        if not ProxyInfo.ip:
            try:
                ProxyInfo.ip = socket.gethostbyname(ProxyInfo.host)
                assert ProxyInfo.ip
            except (socket.gaierror, AssertionError):
                return "Failed to resolve proxy host!"
        try:
            self.remote.connect((ProxyInfo.ip, ProxyInfo.port))
        except socket.error, e:
            if e.errno == errno.ETIMEDOUT:
                return "Connect to proxy server timeout!"
            elif e.errno == errno.WSAEHOSTUNREACH:
                return "Attempted to an unreachable host!"
            else:
                logging.exception("")
                return str(e)


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
                    except socket, e:
                        if e.errno == errno.WSAECONNRESET:
                            self.send_error(httplib.BAD_GATEWAY,
                                "An existing connection was forcibly closed by the remote host")
                        else:
                            logging.exception(str(e))
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
        self.http_response.begin()

    def proxy(self):
        if self.command == "POST" and "Content-Length" not in self.headers:
            self.send_error(httplib.BAD_REQUEST, "POST method without Content-Length header!")
            return
        else:
            error_msg = self.remote_connect()
            if error_msg:
                self.send_error(httplib.BAD_GATEWAY, error_msg)
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
        except socket.error, e:
            if e.errno == errno.WSAECONNABORTED:
                pass
            else:
                logging.exception(str(e))
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
    ProxyInfo.host = "h%d.%s.bj.ie.sogou.com" % (random.randint(0, server_type[1]), server_type[0])

    server = ThreadingHTTPServer((listen_ip, listen_port), Handler)

    print "Sogou Proxy\nRunning on %s\nListening on %s:%d" % (ProxyInfo.host, listen_ip, listen_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        exit()

if __name__ == "__main__":
    main()