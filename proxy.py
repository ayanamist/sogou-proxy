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
__author__ = "ayanamist"
__copyright__ = "Copyright 2012"
__license__ = "GPL"
__version__ = "2.0"
__maintainer__ = "ayanamist"
__email__ = "ayanamist@gmail.com"

import functools
import logging
import os
import signal
import socket
import struct
import time
import ConfigParser

from tornado import gen
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

dummy_cb = lambda _: None
on_close = lambda stream: stream.close() if not stream.closed() else None
randint = lambda min, max: min + int(ord(os.urandom(1)) / 256.0 * max)

def setup_logger(logger):
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)-15s %(name)-8s %(levelname)-5s %(message)s", "%m-%d %H:%M:%S")

    file_handler = logging.FileHandler("%s.log" % os.path.splitext(__file__)[0])
    file_handler.setLevel(logging.ERROR)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stderr_handler = logging.StreamHandler()
    stderr_handler.setLevel(logging.DEBUG)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)


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
    def wait_for_data(self):
        self.read_until("\r\n\r\n", self.on_headers)

    @gen.engine
    def on_headers(self, data):
        http_line, headers_str = data.split("\r\n", 1)
        http_method = http_line.split(" ", 1)[0].upper()
        headers = httputil.HTTPHeaders.parse(headers_str)

        remote = iostream.IOStream(socket.socket())
        remote.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

        self.set_close_callback(functools.partial(on_close, remote))
        remote.set_close_callback(functools.partial(on_close, self))

        yield gen.Task(remote.connect((resolver.resolve(config.sogou_host), 80)))

        timestamp = hex(int(time.time()))[2:].rstrip("L").zfill(8)
        remote.write("%s\r\n%s%s" % (
            http_line,
            "X-Sogou-Auth: %s\r\nX-Sogou-Timestamp: %s\r\nX-Sogou-Tag: %s\r\n" % (
                X_SOGOU_AUTH, timestamp, calc_sogou_hash(timestamp, headers.get("Host", ""))
                ),
            headers_str,
            ))

        if http_method != "CONNECT":
            self.read_bytes(int(headers["Content-Length"]), callback=dummy_cb, streaming_callback=remote.write)
            self.wait_for_data()
        else:
            self.read_until_close(callback=dummy_cb, streaming_callback=remote.write)

        remote.read_until_close(callback=dummy_cb, streaming_callback=self.write)


class ProxyServer(netutil.TCPServer):
    def handle_stream(self, stream, address):
        sock = stream.socket
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        ProxyHandler(sock).wait_for_data()


class Resolver(object):
    _cache = dict()

    def resolve(self, hostname):
        if hostname not in self._cache:
            try:
                ip = socket.gethostbyname(hostname)
            except socket.error:
                return ""
            else:
                self._cache[hostname] = {"ip": ip, "created_time": time.time()}
        return self._cache[hostname]["ip"]

resolver = Resolver()

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
        self.sogou_host = "h%d.%s.bj.ie.sogou.com" % (randint(0, self.server_type[1] - 1), self.server_type[0])
        self.proxy_enabled = self._cp.getboolean("proxy", "enabled")
        self.proxy_host = self._cp.get("proxy", "host")
        self.proxy_port = self._cp.getint("proxy", "port")
        self.proxy_type = self._cp.get("proxy", "type").upper()
        self.handle_proxy()

    def sighup_handler(self, *_):
        self.read(self._config_path)

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

def main():
    setup_logger(logger)

    config.read("%s.ini" % os.path.splitext(__file__)[0])

    SIGHUP = getattr(signal, "SIGHUP", None) # Windows does not have SIGHUP.
    if SIGHUP is not None:
        signal.signal(SIGHUP, config.sighup_handler)

    print "Running on %s\nListening on %s:%d" % (config.sogou_host, config.listen_ip, config.listen_port)
    ProxyServer().listen(config.listen_port, config.listen_ip)
    ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()