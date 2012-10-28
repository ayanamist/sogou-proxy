#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""HTTP utility code shared by clients and servers."""

from __future__ import absolute_import, division, with_statement

import urllib
import re

class HTTPHeaders(dict):
    """A dictionary that maintains Http-Header-Case for all keys.

    Supports multiple values per key via a pair of new methods,
    add() and get_list().  The regular dictionary interface returns a single
    value per key, with multiple values joined by a comma.

    >>> h = HTTPHeaders({"content-type": "text/html"})
    >>> h.keys()
    ['Content-Type']
    >>> h["Content-Type"]
    'text/html'

    >>> h.add("Set-Cookie", "A=B")
    >>> h.add("Set-Cookie", "C=D")
    >>> h["set-cookie"]
    'A=B,C=D'
    >>> h.get_list("set-cookie")
    ['A=B', 'C=D']

    >>> for (k,v) in sorted(h.get_all()):
    ...    print '%s: %s' % (k,v)
    ...
    Content-Type: text/html
    Set-Cookie: A=B
    Set-Cookie: C=D
    """
    def __init__(self, *args, **kwargs):
        # Don't pass args or kwargs to dict.__init__, as it will bypass
        # our __setitem__
        dict.__init__(self)
        self._as_list = {}
        self._last_key = None
        if (len(args) == 1 and len(kwargs) == 0 and
            isinstance(args[0], HTTPHeaders)):
            # Copy constructor
            for k, v in args[0].get_all():
                self.add(k, v)
        else:
            # Dict-style initialization
            self.update(*args, **kwargs)

    # new public methods

    def add(self, name, value):
        """Adds a new value for the given key."""
        norm_name = HTTPHeaders._normalize_name(name)
        self._last_key = norm_name
        if norm_name in self:
            # bypass our override of __setitem__ since it modifies _as_list
            dict.__setitem__(self, norm_name, self[norm_name] + ',' + value)
            self._as_list[norm_name].append(value)
        else:
            self[norm_name] = value

    def get_list(self, name):
        """Returns all values for the given header as a list."""
        norm_name = HTTPHeaders._normalize_name(name)
        return self._as_list.get(norm_name, [])

    def get_all(self):
        """Returns an iterable of all (name, value) pairs.

        If a header has multiple values, multiple pairs will be
        returned with the same name.
        """
        for name, list in self._as_list.iteritems():
            for value in list:
                yield (name, value)

    def parse_line(self, line):
        """Updates the dictionary with a single header line.

        >>> h = HTTPHeaders()
        >>> h.parse_line("Content-Type: text/html")
        >>> h.get('content-type')
        'text/html'
        """
        if line[0].isspace():
            # continuation of a multi-line header
            new_part = ' ' + line.lstrip()
            self._as_list[self._last_key][-1] += new_part
            dict.__setitem__(self, self._last_key,
                             self[self._last_key] + new_part)
        else:
            name, value = line.split(":", 1)
            self.add(name, value.strip())

    @classmethod
    def parse(cls, headers):
        """Returns a dictionary from HTTP header text.

        >>> h = HTTPHeaders.parse("Content-Type: text/html\\r\\nContent-Length: 42\\r\\n")
        >>> sorted(h.iteritems())
        [('Content-Length', '42'), ('Content-Type', 'text/html')]
        """
        h = cls()
        for line in headers.splitlines():
            if line:
                h.parse_line(line)
        return h

    # dict implementation overrides

    def __setitem__(self, name, value):
        norm_name = HTTPHeaders._normalize_name(name)
        dict.__setitem__(self, norm_name, value)
        self._as_list[norm_name] = [value]

    def __getitem__(self, name):
        return dict.__getitem__(self, HTTPHeaders._normalize_name(name))

    def __delitem__(self, name):
        norm_name = HTTPHeaders._normalize_name(name)
        dict.__delitem__(self, norm_name)
        del self._as_list[norm_name]

    def __contains__(self, name):
        norm_name = HTTPHeaders._normalize_name(name)
        return dict.__contains__(self, norm_name)

    def get(self, name, default=None):
        return dict.get(self, HTTPHeaders._normalize_name(name), default)

    def update(self, *args, **kwargs):
        # dict.update bypasses our __setitem__
        for k, v in dict(*args, **kwargs).iteritems():
            self[k] = v

    def copy(self):
        # default implementation returns dict(self), not the subclass
        return HTTPHeaders(self)

    _NORMALIZED_HEADER_RE = re.compile(r'^[A-Z0-9][a-z0-9]*(-[A-Z0-9][a-z0-9]*)*$')
    _normalized_headers = {}

    @staticmethod
    def _normalize_name(name):
        """Converts a name to Http-Header-Case.

        >>> HTTPHeaders._normalize_name("coNtent-TYPE")
        'Content-Type'
        """
        try:
            return HTTPHeaders._normalized_headers[name]
        except KeyError:
            if HTTPHeaders._NORMALIZED_HEADER_RE.match(name):
                normalized = name
            else:
                normalized = "-".join([w.capitalize() for w in name.split("-")])
            HTTPHeaders._normalized_headers[name] = normalized
            return normalized


def url_concat(url, args):
    """Concatenate url and argument dictionary regardless of whether
    url has existing query parameters.

    >>> url_concat("http://example.com/foo?a=b", dict(c="d"))
    'http://example.com/foo?a=b&c=d'
    """
    if not args:
        return url
    if url[-1] not in ('?', '&'):
        url += '&' if ('?' in url) else '?'
    return url + urllib.urlencode(args)


def doctests():
    import doctest
    return doctest.DocTestSuite()
