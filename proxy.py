#!/usr/bin/python

import asyncore
import email.parser
import logging
import os
import random
import signal
import socket
import struct
import sys
import time
import urlparse
import ConfigParser

X_SOGOU_AUTH = "9CD285F1E7ADB0BD403C22AD1D545F40/30/853edc6d49ba4e27"
BUFFER_SIZE = 8192
SERVER_TYPES = [
    ("edu", 16),
    ("ctc", 3),
    ("cnc", 3),
    ("dxt", 3),
]

logger = logging.getLogger(__name__)

def calc_sogou_hash(timestamp, host):
    s = "%s%s%s" % (timestamp, host, "SogouExplorerProxy")
    length = code = len(s)
    dwords = code // 4
    rest = code % 4
    v = struct.unpack("%di%ds" % (dwords, rest), s)
    for i in xrange(dwords):
        vv = v[i]
        a = vv & 0xFFFF
        b = vv >> 16
        code += a
        code ^= ((code << 5) ^ b) << 0xb
        # To avoid overflows
        code &= 0xffffffff
        code += code >> 0xb
    if rest == 3:
        code += ord(s[length - 2]) * 256 + ord(s[length - 3])
        code ^= (code ^ (ord(s[length - 1]) * 4)) << 0x10
        code &= 0xffffffff
        code += code >> 0xb
    elif rest == 2:
        code += ord(s[length - 1]) * 256 + ord(s[length - 2])
        code ^= code << 0xb
        code &= 0xffffffff
        code += code >> 0x11
    elif rest == 1:
        code += ord(s[length - 1])
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


class RequestParser(object):
    def __init__(self, s):
        headers_end = s.rindex("\r\n\r\n")
        if headers_end >= 0:
            headers_start = s.index("\r\n") + 2
            self.request_line = s[:headers_start - 2]
            self.method = self.request_line.split(" ")[0]
            self.headers_str = s[headers_start:headers_end]
            fp = email.parser.FeedParser()
            fp.feed(s[headers_start:headers_end])
            self.headers = fp.close()
            header_host = self.headers.get("Host")
            if header_host is None:
                http_line = s[:headers_end - 2]
                url = http_line.split(" ")[1]
                header_host = urlparse.urlparse(url).netloc.split(":")[0]
                self.headers_str += "\r\nHost: " + header_host
            sogou_timestamp = hex(int(time.time()))[2:].rstrip("L").zfill(8)
            self.headers_str += "\r\nX-Sogou-Auth: " + X_SOGOU_AUTH
            self.headers_str += "\r\nX-Sogou-Timestamp: " + sogou_timestamp
            self.headers_str += "\r\nX-Sogou-Tag: " + calc_sogou_hash(sogou_timestamp, header_host)
            self.partial_content = s[headers_end + 4:]


class ProxyClient(asyncore.dispatcher):
    def __init__(self, other):
        self.other = other
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.connect((config.sogou_ip, 80))

    def handle_read(self):
        data = self.recv(BUFFER_SIZE)
        if data:
            self.other.write_buffer += data
        else:
            if self.other:
                try:
                    self.other.handle_close()
                except socket.error:
                    pass
            self.handle_close()

    def handle_write(self):
        sent = self.send(self.other.read_buffer)
        self.other.read_buffer = self.other.read_buffer[sent:]

    def handle_close(self):
        if self.other:
            try:
                while self.other.read_buffer:
                    self.handle_write()
            except socket.error:
                pass
            self.other.other = None
        try:
            self.close()
        except socket.error:
            pass

    def writable(self):
        return self.other.read_buffer


class ProxyHandler(asyncore.dispatcher):
    def __init__(self, sock):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self._buffer = ""
        self.read_buffer = ""
        self.write_buffer = ""
        self.other = None
        self.is_authed = False
        self.complete_request = False
        self.content_length = 0
        asyncore.dispatcher.__init__(self, sock)

    def handle_read(self):
        data = self.recv(BUFFER_SIZE)
        if data:
            if self.complete_request:
                self.read_buffer += data
            else:
                self._buffer += data
                if not self.is_authed:
                    try:
                        self.rp = RequestParser(self._buffer)
                    except ValueError:
                        pass
                    else:
                        self.read_buffer = self.rp.request_line + "\r\n" + self.rp.headers_str + "\r\n\r\n"
                        self.is_authed = True
                        if not self.other:
                            try:
                                self.other = ProxyClient(self)
                            except socket.error:
                                logger.exception("Fail to create remote socket.")
                                self.handle_close()
                        self._buffer = self.rp.partial_content
                        self.content_length = int(self.rp.headers.get("Content-Length", "0"), 10)
                if self.is_authed and self.content_length <= len(self._buffer):
                    self.read_buffer += self._buffer[:]
                    self._buffer = self._buffer[self.content_length:]
                    if self.rp.method.upper() != "CONNECT":
                        self.is_authed = False
                    else:
                        self.complete_request = True
        else:
            if self.other:
                try:
                    self.other.close()
                except socket.error:
                    pass
            self.handle_close()

    def writable(self):
        return bool(self.write_buffer)

    def handle_write(self):
        sent = self.send(self.write_buffer)
        self.write_buffer = self.write_buffer[sent:]

    def handle_close(self):
        try:
            while self.write_buffer:
                self.handle_write()
        except socket.error:
            pass
        try:
            self.close()
        except socket.error:
            pass


class ProxyServer(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(1)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            ProxyHandler(sock)

    def start(self):
        asyncore.loop()


class Config(object):
    def __init__(self):
        self._cp = ConfigParser.RawConfigParser()
        self.parse()
        self.handle_proxy()

    def parse(self):
        self._cp.read("%s.ini" % os.path.splitext(__file__)[0])
        self.listen_ip = self._cp.get("listen", "ip")
        self.listen_port = self._cp.getint("listen", "port")
        self.server_type = SERVER_TYPES[self._cp.getint("run", "type")]
        self.sogou_host = "h%d.%s.bj.ie.sogou.com" % (random.randint(0, self.server_type[1]), self.server_type[0])
        self._ip = None
        self.proxy_enabled = self._cp.getboolean("proxy", "enabled")
        self.proxy_host = self._cp.get("proxy", "host")
        self.proxy_port = self._cp.getint("proxy", "port")
        self.proxy_type = self._cp.get("proxy", "type").upper()

    @property
    def sogou_ip(self):
        if not self._ip:
            self._ip = socket.gethostbyname(self.sogou_host)
        return self._ip

    def sighup_handler(self, *_):
        self.parse()
        self.handle_proxy()

    def handle_proxy(self):
        if self.proxy_enabled:
            import socks

            proxy_type = getattr(socks, "PROXY_TYPE_" + self.proxy_type)
            socks.setdefaultproxy(proxy_type, self.proxy_host, self.proxy_port)
            socks.wrapmodule(asyncore)
        else:
            asyncore.socket.socket = socket.socket

config = Config()

def main():
    logging.basicConfig(level=logging.ERROR, format='%(asctime)-15s %(name)-8s %(levelname)-8s %(message)s',
        datefmt='%m-%d %H:%M:%S', stream=sys.stderr)

    SIGHUP = getattr(signal, "SIGHUP", None)
    if SIGHUP:
        signal.signal(SIGHUP, config.sighup_handler) # Windows does not have SIGHUP.

    print "Running on %s\nListening on %s:%d" % (config.sogou_host, config.listen_ip, config.listen_port)
    proxy = ProxyServer(config.listen_ip, config.listen_port)
    proxy.start()

if __name__ == "__main__":
    main()