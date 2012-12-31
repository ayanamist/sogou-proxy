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

from tornado import httputil
from tornado import ioloop
from tornado import iostream
from tornado import netutil

SERVER_TYPES = [
    ("edu", 16),
    ("ctc", 4),
    ("cnc", 4),
    ("dxt", 16),
]

logger = logging.getLogger(__name__ if __name__ != "__main__" else "")

def randint(min, max=None):
    if max is None:
        min, max = 0, min
    rand_range = max - min
    rand_bytes = 0
    tmp = rand_range
    while tmp:
        rand_bytes += 1
        tmp >>= 8
    rand_bigint = reduce(lambda x, y: 256 * x + ord(y), os.urandom(rand_bytes), 0)
    return min + rand_bigint * rand_range / (1 << (rand_bytes * 8))


def calc_sogou_auth():
    return "".join(hex(randint(65536))[2:].upper() for _ in xrange(8)) + "/30/853edc6d49ba4e27"

# From http://xiaoxia.org/2011/03/10/depressed-research-about-sogou-proxy-server-authentication-protocol/
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


def on_close_callback_builder(soc):
    def wrapped():
        if soc.writing():
            soc.write("", callback=soc.close())
        else:
            soc.close()

    return wrapped

_sogou_ip = None

def resolve(host):
    if not _sogou_ip:
        global _sogou_ip
        _sogou_ip = socket.gethostbyname(host)
    return _sogou_ip


class ProxyHandler(iostream.IOStream):
    remote = None

    def wait_for_data(self):
        self.read_until("\r\n\r\n", self.on_headers)

    def on_headers(self, data):
        def on_remote_connected():
            http_line, headers_str = data.split("\r\n", 1)
            http_method = http_line.split(" ", 1)[0].upper()
            headers = httputil.HTTPHeaders.parse(headers_str)

            timestamp = hex(int(time.time()))[2:].rstrip("L").zfill(8)
            self.remote.write(
                "%s\r\nX-Sogou-Auth: %s\r\nX-Sogou-Timestamp: %s\r\nX-Sogou-Tag: %s\r\n%s" % (
                    http_line,
                    calc_sogou_auth(),
                    timestamp,
                    calc_sogou_hash(timestamp, headers.get("Host", "")),
                    headers_str
                    )
            )

            if http_method != "CONNECT":
                content_length = int(headers.get("Content-Length", 0))
                if content_length:
                    self.read_bytes(content_length,
                        callback=lambda data: self.remote.write(data) or self.wait_for_data(),
                        streaming_callback=self.remote.write)
                else:
                    self.wait_for_data()
            else:
                self.read_until_close(callback=self.remote.write, streaming_callback=self.remote.write)

            self.remote.read_until_close(callback=self.write, streaming_callback=self.write)

        if not self.remote:
            self.remote = iostream.IOStream(socket.socket())
            self.remote.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

            self.set_close_callback(on_close_callback_builder(self.remote))
            self.remote.set_close_callback(on_close_callback_builder(self))

            self.remote.connect((resolve(config.sogou_host), 80), on_remote_connected)
        else:
            on_remote_connected()


class ProxyServer(netutil.TCPServer):
    def handle_stream(self, stream, address):
        sock = stream.socket
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        ProxyHandler(sock).wait_for_data()


class Config(object):
    _socket_backup = None

    def __init__(self):
        self._cp = ConfigParser.RawConfigParser()

    def read(self, path):
        self._config_path = path
        self._cp.read(path)
        self.listen_ip = self._cp.get("listen", "ip")
        self.listen_port = self._cp.getint("listen", "port")
        self.server_type = SERVER_TYPES[self._cp.getint("run", "type")]
        self.sogou_host = "h%d.%s.bj.ie.sogou.com" % (randint(self.server_type[1]), self.server_type[0])
        self.proxy_enabled = self._cp.getboolean("proxy", "enabled")
        self.proxy_host = self._cp.get("proxy", "host")
        self.proxy_port = self._cp.getint("proxy", "port")
        self.proxy_type = self._cp.get("proxy", "type").upper()
        self.handle_proxy()

    def handle_proxy(self):
        if not self._socket_backup:
            self._socket_backup = socket.socket
        if self.proxy_enabled:
            import socks

            proxy_type = getattr(socks, "PROXY_TYPE_" + self.proxy_type)
            socks.setdefaultproxy(proxy_type, self.proxy_host, self.proxy_port)
            socket.socket = socks.socksocket
        else:
            socket.socket = self._socket_backup

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