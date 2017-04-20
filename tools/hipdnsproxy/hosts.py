#! /usr/bin/env python

# Copyright (c) 2012 Aalto University and RWTH Aachen University.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

"""Hosts file handling for hipdnsproxy."""

import os
import re
import socket
import time


HIT_RE = re.compile(r'(?P<hit>2001:0{0,2}1[0-9a-f]:[0-9a-f:]*)')


def valid_ipv6(addr):
    """Is the string a valid IPv6 address?

    >>> valid_ipv6('::1')
    True
    >>> valid_ipv6('127.0.0.1')
    False
    """
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except socket.error:
        return False


def valid_hit(addr):
    """Is the string a valid Host Identity Tag?

    >>> valid_hit('2001:010::1')
    True
    >>> valid_hit('::1')
    False
    >>> valid_hit('2001:1f::1')
    True
    >>> valid_hit('127.0.0.1')
    False
    """
    if not valid_ipv6(addr):
        return False

    caddr = canonicalize_ipv6(addr)
    if not HIT_RE.match(caddr):
        return False

    return True


def valid_lsi(addr):
    """Is the string a valid Local Scope Identifier?

    >>> valid_lsi('1.0.0.1')
    True
    >>> valid_lsi('127.0.0.1')
    False
    >>> valid_lsi('1.0.1')
    False
    >>> valid_lsi('1.0.0.365')
    False
    >>> valid_lsi('1.foobar')
    False
    """
    parts = addr.split('.')

    if not len(parts) == 4:
        return False

    if not int(parts[0]) == 1:
        return False

    in_range = all([0 <= int(x) < 256 for x in parts])
    if not in_range:
        return False

    return True


def normalize(name):
    """Normalize FQDN.

    >>> normalize('this.is.a.test....')
    'this.is.a.test'
    >>> normalize('this...is..a.test..')
    'this...is..a.test'
    >>> normalize('this..is.a.test')
    'this..is.a.test'
    >>> normalize('this.is.a.test')
    'this.is.a.test'
    """
    name = name.lower()
    parts = name.split('.')
    while parts and parts[-1] == '':
        parts.pop()
    return '.'.join(parts)


def canonicalize_ipv6(addr):
    """Return canonical form of IPv6 address.

    >>> canonicalize_ipv6('ff00:1:02:0:0::3:4')
    'ff00:1:2::3:4'
    >>> canonicalize_ipv6('::1')
    '::1'
    """
    return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6,
                                                              addr))


def addr_to_ptr(addr):
    """Return PTR hostname string for IP address string.

    >>> addr_to_ptr('192.168.1.2')
    '2.1.168.192.in-addr.arpa'
    >>> addr_to_ptr('2001:001e:361f:8a55:6730:6f82:ef36:2fff')
    'f.f.f.2.6.3.f.e.2.8.f.6.0.3.7.6.5.5.a.8.f.1.6.3.e.1.0.0.1.0.0.2.ip6.arpa'
    """
    if valid_ipv6(addr):
        return '%s.ip6.arpa' % '.'.join(reversed(addr.replace(':', '')))

    return '%s.in-addr.arpa' % '.'.join(reversed(addr.split('.')))


def ptr_to_addr(ptr):
    """Return IP address string from PTR hostname string.

    >>> ptr_to_addr('2.1.168.192.in-addr.arpa')
    '192.168.1.2'
    >>> ptr_to_addr('f.f.f.2.6.3.f.e.2.8.f.6.0.3.7.6.5.5.a.8.f.1.6.3.e.1.0.0'
    ...             '.1.0.0.2.ip6.arpa')
    '2001:001e:361f:8a55:6730:6f82:ef36:2fff'
    """
    if '.in-addr.arpa' in ptr:
        return '.'.join(reversed(ptr.split('.')[:4]))
    if '.ip6.arpa' in ptr:
        return ':'.join(['%s' * 4] * 8) % tuple(reversed(ptr.split('.')[:32]))


def _getrecord(name, src):
    """Return address + ttl for hostname from dictionary.

    >>> _getrecord('foo', {'foo': ('127.0.0.1', 0)})
    ('127.0.0.1', 122)
    >>> _getrecord('bar', {}) is None
    True
    >>> _getrecord('baz', {'baz': ('::1', int(time.time())+5)})
    ('::1', 5)
    >>> _getrecord('quux', {'quux': ('::', 5)}) is None
    True
    """
    addr = src.get(normalize(name))
    if addr is None:
        return None
    if addr[1] == 0:
        ttl = 122
    else:
        ttl = addr[1] - int(time.time())
        if ttl < 1:
            del src[normalize(name)]
            return
    return (addr[0], ttl)


def _find_name_for_addr_from_src(addr, src):
    """Find hostname matching address from source.

    >>> _find_name_for_addr_from_src('b::1', {'testhost': ('b::1', 0)})
    'testhost'
    >>> _find_name_for_addr_from_src('127.0.0.1',
    ...                              {'localhost': ('127.0.0.1', 0)})
    'localhost'
    >>> _find_name_for_addr_from_src('foo', {}) is None
    True
    """
    for name, record in src.iteritems():
        naddr = record[0]
        if valid_ipv6(naddr):
            caddr = canonicalize_ipv6(addr)
        else:
            caddr = naddr
        # XXX(ptman): normalize? but that's what's been done until now
        if normalize(addr) == caddr:
            return name


class Hosts:
    """Class for handling a hosts file."""

    def __init__(self, filename, resolv_conf=None):
        self.hostsfile = filename

        if resolv_conf is None:
            resolv_conf = '/etc/resolv.conf'
        self.resolv_conf = resolv_conf

        self.modified = {self.hostsfile: None,
                         self.resolv_conf: None}

        self.suffixes = ()
        self.name_a = {}
        self.name_aaaa = {}
        self.name_hit = {}
        self.recheck()

    def recheck(self):
        """Check if config files have changed and reload as necessary."""
        rc_mtime = os.stat(self.resolv_conf).st_mtime
        if (self.modified[self.resolv_conf] is None or
            rc_mtime > self.modified[self.resolv_conf]):
            self.rcreread()
            self.modified[self.resolv_conf] = rc_mtime
            self.modified[self.hostsfile] = None

        hosts_mtime = os.stat(self.hostsfile).st_mtime
        if (self.modified[self.hostsfile] is None or
            hosts_mtime > self.modified[self.hostsfile]):
            self.reread()
            self.modified[self.hostsfile] = hosts_mtime

    def rcreread(self):
        """Re-read resolv.conf."""
        self.suffixes = ()
        ifile = file(self.resolv_conf)
        while True:
            line = ifile.readline()
            if not line:
                break
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            keyword = parts.pop(0)

            if keyword == 'search':
                self.suffixes = tuple([part.lower() for part in parts])

    def reread(self):
        """Re-read hosts file."""
        name_a = {}
        name_aaaa = {}
        name_hit = {}
        ifile = file(self.hostsfile)

        while True:
            line = ifile.readline()
            if not line:
                break

            line = line.strip()
            if not line or line.startswith('#'):
                continue

            fields = line.split()
            addr = fields.pop(0)

            for name in fields:
                name = normalize(name)

                if valid_hit(addr):
                    name_hit[name] = (addr, 0)
                elif valid_ipv6(addr):
                    name_aaaa[name] = (addr, 0)
                elif valid_lsi(addr):
                    name_a[name] = (addr, 0)

        self.name_a = name_a
        self.name_aaaa = name_aaaa
        self.name_hit = name_hit

    def getaddr(self, addr):
        """Find hostname matching address."""
        if addr is None:
            return
        if valid_ipv6(addr):
            caddr = canonicalize_ipv6(addr)
            if valid_hit(addr):
                return _find_name_for_addr_from_src(caddr, self.name_hit)
            else:
                return _find_name_for_addr_from_src(caddr, self.name_aaaa)
        else:
            return _find_name_for_addr_from_src(addr, self.name_a)

    def geta(self, name):
        """Return LSI record for name."""
        return _getrecord(name, self.name_a)

    def getaaaa(self, name):
        """Return IPv6 record for name."""
        return _getrecord(name, self.name_aaaa)

    def getaaaa_hit(self, name):
        """Return HIT record for name."""
        return _getrecord(name, self.name_hit)

    def cache_name(self, hostname, addr, ttl):
        """Store hostname-address -mapping in cache for ttl duration."""
        valid_to = int(time.time()) + ttl
        if valid_hit(addr):
            self.name_hit[hostname] = (addr, valid_to)
        elif valid_ipv6(addr):
            self.name_aaaa[hostname] = (addr, valid_to)
        else:
            self.name_a[hostname] = (addr, valid_to)

if __name__ == '__main__':
    import doctest
    doctest.testmod(raise_on_error=True)
