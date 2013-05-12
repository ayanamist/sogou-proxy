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
__version__ = "2.3"
__maintainer__ = "ayanamist"
__email__ = "ayanamist@gmail.com"

import errno
import logging
import os
import socket
import struct
import sys
import time
import ConfigParser
from os import path

from tornado import httputil
from tornado import ioloop
from tornado import iostream
from tornado import tcpserver

import daemon

logger = logging.getLogger(__name__ if __name__ != "__main__" else "")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)-14s %(name)-5s %(levelname)-5s %(message)s", "%m-%d %H:%M:%S")

file_handler = logging.FileHandler("%s.log" % path.splitext(__file__)[0])
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

stderr_handler = logging.StreamHandler()
stderr_handler.setLevel(logging.DEBUG)
stderr_handler.setFormatter(formatter)
logger.addHandler(stderr_handler)

try:
    import tornado_pyuv

    ioloop.IOLoop.configure(tornado_pyuv.UVLoop)
except ImportError:
    logger.debug("", exc_info=True)
    if "win" in sys.platform:
        logger.warning("pyuv module not found; using select()")

SERVER_TYPES = [
    ("edu", 4),
    ("ctc", 4),
    ("cnc", 4),
    ("dxt", 4),
]

BAD_GATEWAY_MSG = "HTTP/1.1 502 Bad Gateway\r\n" \
                  "Server: SogouProxy\r\n" \
                  "Connection: close\r\n\r\n"
GET_ADDRINFO_FAILED_MSG = BAD_GATEWAY_MSG + "getaddrinfo failed"


def rand_int(floor, ceil=None):
    if ceil is None:
        floor, ceil = 0, floor
    rand_range = ceil - floor
    rand_bytes = 0
    tmp = rand_range
    while tmp:
        rand_bytes += 1
        tmp >>= 8
    rand_bigint = reduce(lambda x, y: 256 * x + ord(y), os.urandom(rand_bytes), 0)
    return floor + rand_bigint * rand_range / (1 << (rand_bytes * 8))


# From http://xiaoxia.org/2011/03/10/depressed-research-about-sogou-proxy-server-authentication-protocol/
class Sogou(object):
    @staticmethod
    def instance():
        if not hasattr(Sogou, "_instance"):
            Sogou._instance = Sogou()
        return Sogou._instance

    def __init__(self):
        super(Sogou, self).__init__()
        self.auth_str = self.auth()

    def auth(self):
        return "".join(hex(rand_int(65536))[2:].upper() for _ in xrange(8)) + "/30/853edc6d49ba4e27"

    def timestamp(self):
        return hex(int(time.time()))[2:].rstrip("L").zfill(8)

    def tag(self, timestamp, host):
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


class Resolver(object):
    _cache = dict()

    @staticmethod
    def instance():
        if not hasattr(Resolver, "_instance"):
            Resolver._instance = Resolver()
        return Resolver._instance

    def query(self, hostname):
        hostname = hostname.lower()
        result = self._cache.get(hostname)
        if not result:
            result = socket.gethostbyname(hostname)
            self._cache[hostname] = result
        return result


class PairedStream(iostream.IOStream):
    remote = None

    def write(self, data, callback=None):
        try:
            super(PairedStream, self).write(data, callback=callback)
        except iostream.StreamClosedError:
            # Do not use self.close() for it may not run close callback.
            self.on_close()

    def _read_to_buffer(self):
        try:
            return super(PairedStream, self)._read_to_buffer()
        except socket.error as e:
            if e.args[0] == errno.ECONNABORTED:
                # Treat ECONNABORTED as a connection close rather than
                # an error to minimize log spam.
                if not self.closed():
                    self.close(exc_info=True)
                return
            raise

    def on_close(self):
        remote = self.remote
        if remote and not remote.closed():
            if remote.writing():
                remote.write("", callback=remote.close)
            else:
                remote.close()


class ProxyHandler(PairedStream):
    def wait_for_request(self):
        try:
            self.read_until("\r\n\r\n", self.on_request_headers)
        except iostream.StreamClosedError:
            self.on_close()

    def on_request_headers(self, data):
        def on_remote_connected():
            http_method = http_line.split(" ", 1)[0].upper()
            headers = httputil.HTTPHeaders.parse(headers_str)

            sogou = Sogou.instance()
            timestamp = sogou.timestamp()
            self.remote.write(
                "{http_line}\r\n"
                "X-Sogou-Auth: {sogou_auth}\r\n"
                "X-Sogou-Timestamp: {sogou_timestamp}\r\n"
                "X-Sogou-Tag: {sogou_tag}\r\n"
                "{headers}".format(
                    http_line=http_line,
                    sogou_auth=sogou.auth_str,
                    sogou_timestamp=timestamp,
                    sogou_tag=sogou.tag(timestamp, headers.get("Host", "")),
                    headers=headers_str,
                )
            )

            if http_method != "CONNECT":
                content_length = int(headers.get("Content-Length", 0))
                if content_length:
                    self.read_bytes(content_length,
                                    callback=lambda data: self.remote.write(data) or self.wait_for_request(),
                                    streaming_callback=self.remote.write)
                else:
                    self.wait_for_request()
            else:
                self.read_until_close(callback=self.remote.write, streaming_callback=self.remote.write)

            if not self.remote.reading():
                self.remote.read_until_close(callback=self.write, streaming_callback=self.write)

        http_line, headers_str = data.split("\r\n", 1)
        logger.debug(http_line)

        if not self.remote:
            self.remote = PairedStream(socket.socket())
            self.remote.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

            self.set_close_callback(self.remote.on_close)
            self.remote.set_close_callback(self.on_close)

            try:
                self.remote.connect((Resolver.instance().query(Config.instance().sogou_host), 80), on_remote_connected)
            except socket.gaierror as e:
                if e.args[0] == 11001:  # getaddrinfo failed
                    logger.warning("getaddrinfo failed.")
                    self.write(GET_ADDRINFO_FAILED_MSG, callback=self.close)
                else:
                    raise
        else:
            on_remote_connected()


class ProxyServer(tcpserver.TCPServer):
    def handle_stream(self, stream, address):
        sock = stream.socket
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        ProxyHandler(sock).wait_for_request()


class Config(object):
    @staticmethod
    def instance():
        if not hasattr(Config, "_instance"):
            Config._instance = Config()
        return Config._instance

    def __init__(self):
        self._cp = ConfigParser.RawConfigParser()

    def read(self, path):
        self._config_path = path
        self._cp.read(path)
        self.listen_ip = self._cp.get("listen", "ip").strip()
        self.listen_port = self._cp.getint("listen", "port")
        self.server_type = SERVER_TYPES[self._cp.getint("run", "type")]
        self.sogou_host = "h%d.%s.bj.ie.sogou.com" % (rand_int(self.server_type[1]), self.server_type[0])
        self.daemon = self._cp.getboolean("run", "daemon")
        self.pidfile = self._cp.get("run", "pidfile").strip()
        self.proxy_enabled = self._cp.getboolean("proxy", "enabled")
        self.proxy_host = self._cp.get("proxy", "host")
        self.proxy_port = self._cp.getint("proxy", "port")
        self.proxy_type = self._cp.get("proxy", "type").upper()
        self.handle_proxy()

    def handle_proxy(self):
        if self.proxy_enabled:
            import socks

            proxy_type = getattr(socks, "PROXY_TYPE_" + self.proxy_type)
            socks.setdefaultproxy(proxy_type, self.proxy_host, self.proxy_port)
            socket.socket = socks.socksocket


class ProxyDaemon(daemon.Daemon):
    def __init__(self):
        daemon.Daemon.__init__(self, Config.instance().pidfile)

    def run(self):
        config = Config.instance()
        logger.info("Running on %s" % config.sogou_host)
        logger.info("Listening on %s:%d" % (config.listen_ip, config.listen_port))

        ProxyServer().listen(config.listen_port, config.listen_ip)
        try:
            ioloop.IOLoop.instance().start()
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception:
            logger.exception("Error")
        logger.info("Proxy Exit.")


def main():
    config = Config.instance()
    config.read("%s.ini" % path.splitext(__file__)[0])

    daemon = ProxyDaemon()
    if config.daemon and hasattr(os, "fork"):
        daemon.start()
    else:
        daemon.run()


if __name__ == "__main__":
    main()