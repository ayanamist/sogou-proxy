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
__version__ = "1.0"
__maintainer__ = "ayanamist"
__email__ = "ayanamist@gmail.com"

import asyncore
import httplib
import logging
import os
import random
import select
import signal
import socket
import struct
import time
import urlparse
import ConfigParser

X_SOGOU_AUTH = "9CD285F1E7ADB0BD403C22AD1D545F40/30/853edc6d49ba4e27"
BUFFER_SIZE = 65536
SERVER_TYPES = [
    ("edu", 16),
    ("ctc", 3),
    ("cnc", 3),
    ("dxt", 3),
]

NO_RECEIVED_DATA = 0
RECEIVED_DATA = 1
HEADERS_FOUND = 2

logger = logging.getLogger(__name__)

def setup_logger():
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


def patch_asyncore_epoll():
    epoll = getattr(select, "epoll", None)
    if epoll:
        select.poll = epoll
        select.POLLIN = select.EPOLLIN
        select.POLLOUT = select.EPOLLOUT
        select.POLLPRI = select.EPOLLPRI
        select.POLLERR = select.EPOLLERR
        select.POLLHUP = select.EPOLLHUP


class SimpleHTTPHeaders(dict):
    def __init__(self, s):
        dict.__init__(self)
        for line in s.split("\r\n"):
            k, v = line.split(":", 1)
            k = k.rstrip()
            v = v.lstrip()
            self.add(k, v)

    def __setitem__(self, key, value):
        # Python bug: we should first use None to create this key,
        # otherwise dict object will extract the only value of the list.
        key = key.lower()
        dict.__setitem__(self, key, None)
        dict.__setitem__(self, key, [value])

    def __getitem__(self, key):
        value = dict.__getitem__(self, key.lower())
        return value[0]

    def __str__(self):
        return "\r\n".join("%s: %s" % (k.title(), v) for k, v in self.iteritems())

    def __contains__(self, item):
        return dict.__contains__(self, item.lower())

    def add(self, key, value):
        key = key.lower()
        if key not in self:
            self[key] = value
        else:
            self[key].append(value)

    def get(self, k, d=None):
        try:
            v = self[k.lower()]
        except KeyError:
            return d
        else:
            return v

    def getlist(self, key):
        return self[key.lower()]

    def setlist(self, key, new_list):
        self[key.lower()] = new_list

    def iteritems(self):
        for k, lv in dict.iteritems(self):
            for v in lv:
                yield k.title(), v

    def items(self):
        return list(self.iteritems())

    def iterkeys(self):
        for k in dict.iterkeys(self):
            yield k.title()

    def keys(self):
        return list(self.iterkeys())

    def itervalues(self):
        for lv in dict.itervalues(self):
            for v in lv:
                yield v

    def values(self):
        return list(self.itervalues())

    def has_key(self, k):
        return dict.has_key(self, k.lower())


class LoggerDispatcher(object, asyncore.dispatcher):
    def handle_error(self):
        logger.exception("Error")
        self.handle_close()


class ReadWriteDispatcher(LoggerDispatcher):
    read_buffer = ""
    write_buffer = ""
    writing = False
    other = None
    _handle_status = NO_RECEIVED_DATA

    def writable(self):
        return bool(self.write_buffer)

    def handle_write(self):
        if self.writable():
            self.writing = True
            sent = self.send(self.write_buffer)
            if sent:
                self.writing = False
                self.write_buffer = self.write_buffer[sent:]
            else:
                self.handle_close()

    def handle_close(self):
        self.closing = True
        if not self.writing:
            while self.writable() and self.handle_write() > 0:
                pass
        if self.other and not self.other.closing:
            self.other.handle_close()
        self.close()


class ProxyClient(ReadWriteDispatcher):
    def __init__(self, other):
        self.other = other

        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        self.connect((config.sogou_ip, 80))

    def __get_read_buffer(self):
        if self.other:
            return self.other.write_buffer
        elif not self.closing:
            self.handle_close()
            return ""

    def __set_read_buffer(self, value):
        self.other.write_buffer = value

    read_buffer = property(__get_read_buffer, __set_read_buffer)

    def __get_write_buffer(self):
        if self.other:
            return self.other.read_buffer
        elif not self.closing:
            self.handle_close()
            return ""

    def __set_write_buffer(self, value):
        self.other.read_buffer = value

    write_buffer = property(__get_write_buffer, __set_write_buffer)

    def handle_read(self):
        data = self.recv(BUFFER_SIZE)
        if data:
            self._handle_status = RECEIVED_DATA
            self.read_buffer += data
        else:
            if self._handle_status == NO_RECEIVED_DATA:
                self.other.send_error(502, "No data received")
            else:
                self.handle_close()


class ProxyHandler(ReadWriteDispatcher):
    _content_remain_length = 0
    _unhandled_buffer = ""

    def __init__(self, sock):
        asyncore.dispatcher.__init__(self, sock)
        self.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

    def parse_request(self):
        headers_end = self._unhandled_buffer.rfind("\r\n\r\n")
        if headers_end >= 0:
            headers_start = self._unhandled_buffer.find("\r\n") + 2
            if headers_start >= 0:
                self.request_line = self._unhandled_buffer[:headers_start-2]
                self.method = self.request_line.split(" ")[0].upper()
                self.headers = SimpleHTTPHeaders(self._unhandled_buffer[headers_start:headers_end])
                header_host = self.headers.get("Host")
                if header_host is None:
                    http_line = self._unhandled_buffer[:headers_end-2]
                    url = http_line.split(" ")[1]
                    header_host = urlparse.urlparse(url).netloc.split(":")[0]
                    self.headers["Host"] = header_host
                self._unhandled_buffer = self._unhandled_buffer[headers_end+4:]
                return True
        return False

    def send_error(self, code, message=None):
        response_dict = {
            "status_code": code,
            "status_message": httplib.responses.get(code, "???"),
        }
        if message is None:
            response_dict["message"] = response_dict["status_message"]
        else:
            response_dict["message"] = message
        response_dict["content_length"] = len(response_dict["message"])
        self.write_buffer = "HTTP/1.0 %(status_code)d %(status_message)s\r\nContent-Type: text/plain\r\nContent-Length: %(content_length)d\r\n\r\n%(message)s" % response_dict
        self.handle_close()

    def handle_read(self):
        data = self.recv(BUFFER_SIZE)
        if data:
            self._unhandled_buffer += data
        if self._handle_status < HEADERS_FOUND:
            if self.parse_request():
                self._handle_status = HEADERS_FOUND
                meth = getattr(self, "handle_http_request", None)
                if meth:
                    meth()
                self.read_buffer += "%s\r\n%s\r\n\r\n" % (self.request_line, str(self.headers))
                if "Content-Length" in self.headers:
                    self._content_remain_length = int(self.headers["Content-Length"])
        if self._handle_status == HEADERS_FOUND:
            if self._content_remain_length > 0:
                _unhandled_buffer_length = len(self._unhandled_buffer)
                self.read_buffer += self._unhandled_buffer[:self._content_remain_length]
                self._unhandled_buffer = self._unhandled_buffer[self._content_remain_length:]
                if _unhandled_buffer_length > self._content_remain_length:
                    self._content_remain_length = 0
                else:
                    self._content_remain_length -= _unhandled_buffer_length
            if self._content_remain_length <= 0:
                if self.method == "CONNECT":
                    self.read_buffer += self._unhandled_buffer
                    self._unhandled_buffer = ""
                else:
                    self._handle_status = RECEIVED_DATA
        if not data:
            return self.handle_close()


class SogouHandler(ProxyHandler):
    def add_sogou_headers(self):
        sogou_timestamp = hex(int(time.time()))[2:].rstrip("L").zfill(8)
        self.headers["X-Sogou-Auth"] = X_SOGOU_AUTH
        self.headers["X-Sogou-Timestamp"] = sogou_timestamp
        self.headers["X-Sogou-Tag"] = calc_sogou_hash(sogou_timestamp, self.headers["Host"])

    def handle_http_request(self):
        self.add_sogou_headers()
        if not self.other or not self.other.connected:
            try:
                self.other = ProxyClient(self)
            except socket.error as e:
                return self.send_error(httplib.BAD_GATEWAY, "Failed to connect: %r" % e)


class ProxyServer(LoggerDispatcher):
    def __init__(self, host, port, request_queue_size=5):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(request_queue_size)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            SogouHandler(sock)

    def serve_forever(self):
        asyncore.loop(use_poll=True)


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
        self.sogou_host = "h%d.%s.bj.ie.sogou.com" % (random.randint(0, self.server_type[1] - 1), self.server_type[0])
        self._ip = None
        self.proxy_enabled = self._cp.getboolean("proxy", "enabled")
        self.proxy_host = self._cp.get("proxy", "host")
        self.proxy_port = self._cp.getint("proxy", "port")
        self.proxy_type = self._cp.get("proxy", "type").upper()
        self.handle_proxy()

    @property
    def sogou_ip(self):
        if not self._ip:
            self._ip = socket.gethostbyname(self.sogou_host)
        return self._ip

    def sighup_handler(self, *_):
        self.read(self._config_path)

    def handle_proxy(self):
        if not self._socket_backup:
            self._socket_backup = socket.socket
        if self.proxy_enabled:
            import socks

            proxy_type = getattr(socks, "PROXY_TYPE_" + self.proxy_type)
            socks.setdefaultproxy(proxy_type, self.proxy_host, self.proxy_port)
            socks.wrapmodule(asyncore)
        else:
            asyncore.socket.socket = self._socket_backup

config = Config()

def main():
    setup_logger()
    patch_asyncore_epoll()

    config.read("%s.ini" % os.path.splitext(__file__)[0])

    SIGHUP = getattr(signal, "SIGHUP", None) # Windows does not have SIGHUP.
    if SIGHUP is not None:
        signal.signal(SIGHUP, config.sighup_handler)

    print "Running on %s\nListening on %s:%d" % (config.sogou_host, config.listen_ip, config.listen_port)
    ProxyServer(config.listen_ip, config.listen_port).serve_forever()

if __name__ == "__main__":
    main()