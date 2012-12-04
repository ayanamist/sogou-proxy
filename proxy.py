#!/usr/bin/python
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import absolute_import

__author__ = "ayanamist"
__copyright__ = "Copyright 2012"
__license__ = "GPL"
__version__ = "2.2"
__maintainer__ = "ayanamist"
__email__ = "ayanamist@gmail.com"

import logging
import os
import socket
import struct
import time
import ConfigParser
from os import path

try:
    import tornado_pyuv

    tornado_pyuv.install()
except ImportError:
    pass
from tornado import httputil
from tornado import ioloop
from tornado import iostream
from tornado import netutil

X_SOGOU_AUTH = "9CD285F1E7ADB0BD403C22AD1D545F40/30/853edc6d49ba4e27"
SERVER_TYPES = [
    ("edu", 16),
    ("ctc", 4),
    ("cnc", 4),
    ("dxt", 16),
]

logger = logging.getLogger(__name__ if __name__ != "__main__" else "")

def randint(min, max):
    return min + int(ord(os.urandom(1)) / 256.0 * max)


def calc_sogou_hash(timestamp, host):
    s = timestamp + host + "SogouExplorerProxy"
    length = code = len(s)
    dwords = code / 4
    rest = code % 4
    fmt = "%di%ds" % (dwords, rest)
    v = struct.unpack(fmt, s)
    for i in xrange(dwords):
        vv = v[i]
        a = vv & 0xffff
        b = vv >> 16
        code += a
        code ^= ((code << 5) ^ b) << 11
        # To avoid overflows
        code &= 0xffffffff
        code += code >> 11
    if rest == 3:
        code += ord(s[length - 2]) * 256 + ord(s[length - 3])
        code ^= (code ^ (ord(s[length - 1]) * 4)) << 16
        code &= 0xffffffff
        code += code >> 11
    elif rest == 2:
        code += ord(s[length - 1]) * 256 + ord(s[length - 2])
        code ^= code << 11
        code &= 0xffffffff
        code += code >> 17
    elif rest == 1:
        code += ord(s[length - 1])
        code ^= code << 10
        code &= 0xffffffff
        code += code >> 1
    code ^= code * 8
    code &= 0xffffffff
    code += code >> 5
    code ^= code << 4
    code &= 0xffffffff
    code += code >> 17
    code ^= code << 25
    code &= 0xffffffff
    code += code >> 6
    code &= 0xffffffff
    return hex(code)[2:].rstrip("L").zfill(8)


class ProxyHandler(iostream.IOStream):
    def wait_for_request(self):
        self.read_until("\r\n\r\n", self.on_headers_end)

    def on_headers_end(self, request_str):
        def on_request_sent():
            if request_method == "CONNECT":
                self.read_until_close(callback=self.remote.write, streaming_callback=self.remote.write)
                self.remote.read_until_close(callback=self.write, streaming_callback=self.write)
            else:
                if content_length:
                    self.read_bytes(content_length, callback=self.on_request_body_end,
                        streaming_callback=self.remote.write)
                else:
                    self.wait_for_response()

        request_line, headers_str = request_str.split("\r\n", 1)
        headers = httputil.HTTPHeaders.parse(headers_str)
        request_method = request_line.split(" ", 1)[0]
        content_length = int(headers.get("Content-Length", 0))

        self.remote = iostream.IOStream(socket.socket())
        self.remote.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

        self.set_close_callback(self.remote.close)
        self.remote.set_close_callback(self.close)

        self.remote.connect((config.sogou_host, 80))

        timestamp = hex(int(time.time()))[2:].rstrip("L").zfill(8)

        new_request_str = "%s\r\nX-Sogou-Auth: %s\r\nX-Sogou-Timestamp: %s\r\nX-Sogou-Tag: %s\r\n%s" % (
            request_line, X_SOGOU_AUTH, timestamp,
            calc_sogou_hash(timestamp, headers.get("Host", "")),
            headers_str)
        self.remote.write(new_request_str, callback=on_request_sent)

    def on_request_body_end(self, data):
        self.remote.write(data)
        self.wait_for_response()

    def wait_for_response(self):
        self.remote.read_until("\r\n\r\n", self.on_response_headers_end)

    def on_response_headers_end(self, response_str):
        status_line, headers_str = response_str.split("\r\n", 1)
        headers = httputil.HTTPHeaders.parse(headers_str)
        self.write(response_str)
        content_length = headers.get("Content-Length")
        if content_length is None:
            self.remote.read_until_close(callback=self.write, streaming_callback=self.write)
        else:
            content_length = int(content_length)
            if content_length:
                self.remote.read_bytes(content_length, callback=self.on_response_body_end,
                    streaming_callback=self.write)
            else:
                self.wait_for_request()

    def on_response_body_end(self, data):
        self.write(data)
        self.wait_for_request()


class ProxyServer(netutil.TCPServer):
    def handle_stream(self, stream, address):
        sock = stream.socket
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        ProxyHandler(sock).wait_for_request()


class Config(object):
    def __init__(self):
        self._cp = ConfigParser.RawConfigParser()

    def read(self, path):
        self._config_path = path
        self._cp.read(path)
        self.listen_ip = self._cp.get("listen", "ip")
        self.listen_port = self._cp.getint("listen", "port")
        self.server_type = SERVER_TYPES[self._cp.getint("run", "type")]
        self.sogou_host = "h%d.%s.bj.ie.sogou.com" % (randint(0, self.server_type[1] - 1), self.server_type[0])
        self.proxy_enabled = self._cp.getboolean("proxy", "enabled")
        self.proxy_host = self._cp.get("proxy", "host")
        self.proxy_port = self._cp.getint("proxy", "port")
        self.proxy_type = self._cp.get("proxy", "type").upper()

        if self.proxy_enabled:
            import socks

            proxy_type = getattr(socks, "PROXY_TYPE_" + self.proxy_type)
            socks.setdefaultproxy(proxy_type, self.proxy_host, self.proxy_port)
            socket.socket = socks.socksocket

config = Config()

def setup_logger(logger):
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)-15s %(name)-8s %(levelname)-5s %(message)s", "%m-%d %H:%M:%S")

    file_handler = logging.FileHandler("%s.log" % path.splitext(__file__)[0])
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stderr_handler = logging.StreamHandler()
    stderr_handler.setLevel(logging.DEBUG)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)


def main():
    setup_logger(logger)

    config.read("%s.ini" % path.splitext(__file__)[0])

    logger.info("Running on %s" % config.sogou_host)
    logger.info("Listening on %s:%d" % (config.listen_ip, config.listen_port))

    ProxyServer().listen(config.listen_port, config.listen_ip)
    try:
        ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        pass
    except Exception:
        logger.exception("Error")
    logger.info("Proxy Exit.")

if __name__ == "__main__":
    main()