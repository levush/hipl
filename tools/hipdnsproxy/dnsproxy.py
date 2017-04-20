#!/usr/bin/env python

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

"""HIP name look-up daemon for HIPL hosts file and DNS servers."""

# Usage: Basic usage without any command line options.
#        See getopt() for the options.
#
# Working test cases with hipdnsproxy
# - Interoperates with libc and dnsmasq
# - Resolvconf(on/off) + dnsmasq (on/off)
#    - initial look up (check HIP and non-hip look up)
#      - check that ctrl+c restores /etc/resolv.conf
#    - change access network (check HIP and non-hip look up)
#      - check that ctrl+c restores /etc/resolv.conf
# - Watch out for cached entries! Restart dnmasq and hipdnsproxy after
#   each test.
# - Test name resolution with following methods:
#   - Non-HIP records
#   - Hostname to HIT resolution
#     - HITs and LSIs from /etc/hip/hosts
#     - On-the-fly generated LSI; HIT either from from DNS or hosts
#     - HI records from DNS
#   - PTR records: maps HITs to hostnames from /etc/hip/hosts
#
# Actions to resolv.conf files and dnsproxy hooking:
# - Dnsmasq=on, revolvconf=on: only hooks dnsmasq
# - Dnsmasq=off, revolvconf=on: rewrites /etc/resolvconf/run/resolv.conf
# - Dnsmasq=on, revolvconf=off: hooks dnsmasq and rewrites /etc/resolv.conf
# - Dnsmasq=off, revolvconf=off: rewrites /etc/resolv.conf
#
# TBD:
# - rewrite the code to more object oriented
# - the use of alternative (multiple) dns servers
# - implement TTLs for cache
#   - applicable to HITs, LSIs and IP addresses
#   - host files: forever (purged when the file is changed)
#   - dns records: follow DNS TTL
# - bind to ::1, not 127.0.0.1 (setsockopt blah blah)
# - remove hardcoded addresses from ifconfig commands
# - compatibility with "unbound"

import copy
import errno
import logging
import logging.handlers
import os
import pprint
import re
import select
import signal
import socket
import subprocess
import sys
import time

#local imports

# prepending (instead of appending) to make sure hosts.py does not
# collide with the system default
import DNS
import hosts
import resolvconf
import util


DEFAULT_HOSTS = '/etc/hosts'
LSI_RE = re.compile(r'(?P<lsi>1\.\d+\.\d+\.\d+)')


def usage(unused_utyp, *msg):
    """Print usage instructions and exit."""
    sys.stderr.write('Usage: %s\n' % os.path.split(sys.argv[0])[1])
    if msg:
        sys.stderr.write('Error: %r\n' % msg)

    sys.exit(1)


MYID = None


def add_hit_ip_map(hit, addr):
    """Add IP for HIT."""
    logging.info('Associating HIT %s with IP %s', hit, addr)
    try:
        subprocess.check_call(['hipconf', 'daemon', 'add', 'map', hit, addr],
                              stdout=open(os.devnull, 'w'),
                              stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        logging.error('Got error from `hipconf daemon ...`. Is hipd up?')


def hit_to_lsi(hit):
    """Return LSI for HIT if found."""
    proc = subprocess.Popen(['hipconf', 'daemon', 'hit-to-lsi', hit],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)

    if proc.returncode == 254:
        logging.error('Cannot contact hipd. Is it running?')
        return

    output = proc.stdout

    try:
        for line in output:
            match = LSI_RE.search(line)
            if match:
                return match.group('lsi')
    except IOError:
        logging.error('Cannot read from `hipconf daemon ...`. Is hipd up?')


def lsi_to_hit(lsi):
    """Return HIT for LSI if found."""
    proc = subprocess.Popen(['hipconf', 'daemon', 'lsi-to-hit', lsi],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)

    if proc.returncode == 254:
        logging.error('Cannot contact hipd. Is it running?')
        return

    output = proc.stdout

    try:
        for line in output:
            match = hosts.HIT_RE.search(line)
            if match:
                return match.group('hit')
    except IOError:
        logging.error('Cannot read from `hipconf daemon ...`. Is hipd up?')


def is_reverse_hit_query(name):
    """Check if the query is a reverse query to a HIT."""
    if (name.endswith('.1.0.0.1.0.0.2.hit-to-ip.infrahip.net') and
        len(name) == 86):
        return True
    return False


class DNSProxy:
    """HIP DNS proxy main class."""
    re_nameserver = re.compile(r'nameserver\s+(\S+)$')

    def __init__(self, bind_ip=None, bind_port=None, disable_lsi=False,
                 dns_timeout=2.0, fork=False, hiphosts=None, hostsnames=None,
                 pidfile=None, prefix=None, server_ip=None, server_port=None):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.connected = False
        self.disable_lsi = disable_lsi
        self.dns_timeout = dns_timeout
        self.fork = fork
        self.hiphosts = hiphosts
        self.hostsnames = hostsnames
        self.pidfile = pidfile
        self.prefix = prefix
        self.server_ip = server_ip
        self.server_port = server_port

        self.resolvconf = resolvconf.ResolvConf()

        if self.hostsnames is None:
            self.hostsnames = []

        self.clisock = None
        self.servsock = None
        self.app_timeout = 1
        self.hosts_ttl = 122
        self.sent_queue = []
        self.hosts = None
        self.query_id = 1
        # Keyed by ('server_ip',server_port,query_id) tuple
        self.sent_queue_d = {}
        # required for ifconfig and hipconf in Fedora
        # (rpm and "make install" targets)
        os.environ['PATH'] += ':/sbin:/usr/sbin:/usr/local/sbin'

    def add_query(self, server_ip, server_port, query_id, query):
        """Add a pending DNS query"""
        key = (server_ip, server_port, query_id)
        value = (key, time.time(), query)
        self.sent_queue.append(value)
        self.sent_queue_d[key] = value

    def find_query(self, server_ip, server_port, query_id):
        """Find a pending DNS query"""
        key = (server_ip, server_port, query_id)
        query = self.sent_queue_d.get(key)
        if query:
            idx = self.sent_queue.index(query)
            self.sent_queue.pop(idx)
            del self.sent_queue_d[key]
            return query[2]
        return None

    def clean_queries(self):
        """Clean old unanswered queries"""
        texp = time.time() - 30
        while self.sent_queue:
            if self.sent_queue[0][1] < texp:
                # TODO(ptman): test that key is used properly in del
                key = self.sent_queue[0][0]
                self.sent_queue.pop(0)
                del self.sent_queue_d[key]
            else:
                break
        return

    def parameter_defaults(self):
        """Missing default parameters."""
        env = os.environ
        if self.server_ip is None:
            self.server_ip = env.get('SERVER', None)

        if self.server_port is None:
            server_port = env.get('SERVERPORT', None)
            if server_port is not None:
                self.server_port = int(server_port)

        if self.server_port is None:
            self.server_port = 53

        if self.bind_ip is None:
            self.bind_ip = env.get('IP', None)

        if self.bind_ip is None:
            self.bind_ip = '127.0.0.53'

        if self.bind_port is None:
            bind_port = env.get('PORT', None)
            if bind_port is not None:
                self.bind_port = int(bind_port)

        if self.bind_port is None:
            self.bind_port = 53

    def hosts_recheck(self):
        """Recheck all hosts files."""
        for hostsdb in self.hosts:
            hostsdb.recheck()

    def getaddr(self, ahn):
        """Get a hostname matching address."""
        for hostsdb in self.hosts:
            result = hostsdb.getaddr(ahn)
            if result:
                return result

    def getaaaa(self, ahn):
        """Get an AAAA record from the hosts files."""
        for hostsdb in self.hosts:
            result = hostsdb.getaaaa(ahn)
            if result:
                return result

    def getaaaa_hit(self, ahn):
        """Get and HIT record from the hosts files."""
        for hostsdb in self.hosts:
            result = hostsdb.getaaaa_hit(ahn)
            if result:
                return result

    def cache_name(self, name, addr, ttl):
        """Cache the name-address mapping with ttl in all hosts files."""
        for hostsdb in self.hosts:
            hostsdb.cache_name(name, addr, ttl)

    def geta(self, ahn):
        """Get an A record from the hosts files."""
        for hostsdb in self.hosts:
            result = hostsdb.geta(ahn)
            if result:
                return result

    def killold(self):
        """Kill process with PID from pidfile."""
        try:
            ifile = open(self.pidfile, 'r')
        except IOError, ioe:
            if ioe[0] == errno.ENOENT:
                return
            else:
                logging.error('Error opening pid file: %s', ioe)
                sys.exit(1)

        try:
            os.kill(int(ifile.readline().rstrip()), signal.SIGTERM)
        except OSError, ose:
            if ose[0] == errno.ESRCH:
                ifile.close()
                return
            else:
                logging.error('Error terminating old process: %s', ose)
                sys.exit(1)

        time.sleep(3)
        ifile.close()

    def recovery(self):
        """Recover from being harshly killed."""
        try:
            ifile = open(self.pidfile, 'r')
        except IOError, ioe:
            if ioe[0] == errno.ENOENT:
                return
            else:
                logging.error('Error opening pid file: %s', ioe)
                sys.exit(1)

        ifile.readline()
        global MYID
        MYID = ifile.readline().rstrip()
        ifile.close()
        self.resolvconf.restore()

    def savepid(self):
        """Write PID and MYID to pidfile."""
        try:
            ofile = open(self.pidfile, 'w')
        except IOError, ioe:
            logging.error('Error opening pid file for writing: %s', ioe)
            sys.exit(1)

        global MYID
        MYID = '%d-%d' % (time.time(), os.getpid())
        ofile.write('%d\n' % (os.getpid(),))
        ofile.write('%s\n' % MYID)
        ofile.close()

    def write_local_hits_to_hosts(self):
        """Add local HITs to the hosts files.

        Otherwise certain services (sendmail, cups, httpd) timeout when they
        are started and they query the local HITs from the DNS.

        FIXME: should we really write the local hits to a file rather than just
        adding them to the cache?
        """
        localhit = []
        proc = subprocess.Popen(['ifconfig', 'dummy0'],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT).stdout
        line = proc.readline()
        while line:
            start = line.find('2001:1')
            end = line.find('/28')
            if start != -1 and end != -1:
                hit = line[start:end]
                if not self.getaddr(hit):
                    localhit.append(hit)

            line = proc.readline()

        proc.close()
        ofile = open(self.hiphosts, 'a')
        for i in range(len(localhit)):
            ofile.write('%s\tlocalhit%s\n' % (localhit[i], i + 1))

        ofile.close()

    def hip_cache_lookup(self, packet):
        """Make a cache lookup."""
        result = None
        qname = packet['questions'][0][0]
        qtype = packet['questions'][0][1]

        if self.prefix and qname.startswith(self.prefix):
            qname = qname[len(self.prefix):]

        # convert 1.2....1.0.0.1.0.0.2.ip6.arpa to a HIT and
        # map host name to address from cache
        if qtype == DNS.Type.PTR:
            lr_ptr = None
            addr_str = hosts.ptr_to_addr(qname)
            if (not self.disable_lsi and addr_str is not None and
                hosts.valid_lsi(addr_str)):
                addr_str = lsi_to_hit(addr_str)

            lr_ptr = self.getaddr(addr_str)
            lr_aaaa_hit = None
        else:
            lr_a = self.geta(qname)
            lr_aaaa = self.getaaaa(qname)
            lr_aaaa_hit = self.getaaaa_hit(qname)

        if (lr_aaaa_hit is not None and
            (not self.prefix or
             packet['questions'][0][0].startswith(self.prefix))):
            if lr_a is not None:
                add_hit_ip_map(lr_aaaa_hit[0], lr_a[0])

            if lr_aaaa is not None:
                add_hit_ip_map(lr_aaaa_hit[0], lr_aaaa[0])

            if qtype == DNS.Type.AAAA:
                result = lr_aaaa_hit
            elif qtype == DNS.Type.A and not self.disable_lsi:
                lsi = hit_to_lsi(lr_aaaa_hit[0])
                if lsi is not None:
                    result = (lsi, lr_aaaa_hit[1])

        elif self.prefix and packet['questions'][0][0].startswith(self.prefix):
            result = None
        elif qtype == DNS.Type.AAAA:
            result = lr_aaaa
        elif qtype == DNS.Type.A:
            result = lr_a
        elif qtype == DNS.Type.PTR and lr_ptr is not None:
            result = (lr_ptr, self.hosts_ttl)

        if result is not None:
            packet['answers'].append([packet['questions'][0][0], qtype, 1,
                                      result[1], result[0]])
            packet['ancount'] = len(packet['answers'])
            packet['qr'] = 1
            return True

        return False

    def hip_lookup(self, packet):
        """Make a lookup."""
        qname = packet['questions'][0][0]
        qtype = packet['questions'][0][1]

        dns_hit_found = False
        for answer in packet['answers']:
            if answer[1] == DNS.Type.HIP:
                dns_hit_found = True
                break

        lsi = None
        hit_found = dns_hit_found is not None
        if hit_found:
            hit_ans = []
            lsi_ans = []

            for answer in packet['answers']:
                if answer[1] != DNS.Type.HIP:
                    continue

                hit = socket.inet_ntop(socket.AF_INET6, answer[7])
                hit_ans.append([qname, DNS.Type.AAAA, 1, answer[3], hit])

                if qtype == DNS.Type.A and not self.disable_lsi:
                    lsi = hit_to_lsi(hit)
                    if lsi is not None:
                        lsi_ans.append([qname, 1, 1, self.hosts_ttl, lsi])

                self.cache_name(qname, hit, answer[3])

        if qtype == DNS.Type.AAAA and hit_found:
            packet['answers'] = hit_ans
        elif lsi is not None:
            packet['answers'] = lsi_ans
        else:
            packet['answers'] = []

        packet['ancount'] = len(packet['answers'])

    def handle_query(self, packet, sender):
        """Handle DNS query from downstream client."""
        qtype = packet['questions'][0][1]

        sent_answer = False

        if qtype in (DNS.Type.A, DNS.Type.AAAA, DNS.Type.PTR):
            if self.hip_cache_lookup(packet):
                try:
                    outbuf = DNS.Serialize(packet).get_packet()
                    self.servsock.sendto(outbuf, sender)
                    sent_answer = True
                except socket.error:
                    logging.exception('Exception:')

        elif (self.prefix and
              packet['questions'][0][0].startswith(
                  self.prefix)):
            # Query with HIP prefix for unsupported RR type.
            # Send empty response.
            packet['qr'] = 1
            try:
                outbuf = DNS.Serialize(packet).get_packet()
                self.servsock.sendto(outbuf, sender)
                sent_answer = True
            except socket.error:
                logging.exception('Exception:')

        if self.connected and not sent_answer:
            logging.info('Query type %d for %s from %s',
                         qtype, packet['questions'][0][0],
                         (self.server_ip, self.server_port))

            query = (packet, sender[0], sender[1], qtype)
            # FIXME: Should randomize for security
            self.query_id = (self.query_id % 65535) + 1
            pckt = copy.copy(packet)
            pckt['id'] = self.query_id
            if ((qtype == DNS.Type.AAAA or
                 (qtype == DNS.Type.A and
                  not self.disable_lsi)) and
                not is_reverse_hit_query(
                    packet['questions'][0][0])):

                if not self.prefix:
                    pckt['questions'][0][1] = DNS.Type.HIP

                if (self.prefix and
                    pckt['questions'][0][0].startswith(
                        self.prefix)):
                    pckt['questions'][0][0] = pckt[
                        'questions'][0][0][len(self.prefix):]
                    pckt['questions'][0][1] = DNS.Type.HIP

            if qtype == DNS.Type.PTR and not self.disable_lsi:
                qname = packet['questions'][0][0]
                addr_str = hosts.ptr_to_addr(qname)
                if (addr_str is not None and
                    hosts.valid_lsi(addr_str)):
                    query = (packet, sender[0], sender[1],
                             qname)
                    hit_str = lsi_to_hit(addr_str)
                    if hit_str is not None:
                        pckt['questions'][0][0] = hosts.addr_to_ptr(hit_str)

            outbuf = DNS.Serialize(pckt).get_packet()
            self.clisock.sendto(outbuf, (self.server_ip,
                                         self.server_port))

            self.add_query(self.server_ip, self.server_port,
                           self.query_id, query)

    def handle_response(self, packet, sender):
        """Handle DNS response from upstream server."""
        if packet['qdcount'] == 0:
            logging.warn('Bad response from upstream server: %s',
                         pprint.pformat(packet))
            return

        # Find original query
        query_id_o = packet['id']
        query_o = self.find_query(sender[0], sender[1],
                                  query_id_o)
        if query_o and packet['qdcount'] > 0:
            qname = packet['questions'][0][0]
            qtype = packet['questions'][0][1]
            send_reply = True
            query_again = False
            hit_found = False
            packet_o = query_o[0]
            # Replace with the original query id
            packet['id'] = packet_o['id']

            if qtype == DNS.Type.HIP and query_o[3] in (DNS.Type.A,
                                                        DNS.Type.AAAA):
                # Restore qtype
                packet['questions'][0][1] = query_o[3]
                self.hip_lookup(packet)
                if packet['ancount'] > 0:
                    hit_found = True

                if (not self.prefix or
                    (hit_found and not (self.getaaaa(qname) or
                                        self.geta(qname)))):
                    query_again = True
                    send_reply = False
                elif self.prefix:
                    hit_found = True
                    packet['questions'][0][0] = (
                        self.prefix + packet['questions'][0][0])
                    for answer in packet['answers']:
                        answer[0] = self.prefix + answer[0]

            elif qtype in (DNS.Type.A, DNS.Type.AAAA):
                hit = self.getaaaa_hit(qname)
                ip6 = self.getaaaa(qname)
                ip4 = self.geta(qname)
                for answer in packet['answers']:
                    if answer[1] in (DNS.Type.A, DNS.Type.AAAA):
                        self.cache_name(qname, answer[4],
                                        answer[3])

                if hit is not None:
                    for answer in packet['answers']:
                        if (answer[1] == DNS.Type.A or
                            (answer[1] == DNS.Type.AAAA and not
                             hosts.valid_hit(answer[4]))):
                            add_hit_ip_map(hit[0], answer[4])

                    # Reply with HIT/LSI once it's been mapped
                    # to an IP
                    if ip6 is None and ip4 is None:
                        if (packet_o['ancount'] == 0 and
                            not self.prefix):
                            # No LSI available. Return IPv4
                            tmp = packet['answers']
                            packet = packet_o
                            packet['answers'] = tmp
                            packet['ancount'] = len(
                                packet['answers'])
                        else:
                            packet = packet_o
                            if self.prefix:
                                packet['questions'][0][0] = (
                                    self.prefix + packet['questions'][0][0])
                                for answer in packet['answers']:
                                    answer[0] = (self.prefix +
                                                 answer[0])

                    else:
                        send_reply = False

                elif query_o[3] == 0:
                    # Prefix is in use
                    # IP was queried for cache only
                    send_reply = False

            elif qtype == DNS.Type.PTR and isinstance(query_o[3],
                                                      str):
                packet['questions'][0][0] = query_o[3]
                for answer in packet['answers']:
                    answer[0] = query_o[3]

            if query_again:
                if hit_found:
                    qtypes = [DNS.Type.AAAA, DNS.Type.A]
                    pckt = copy.deepcopy(packet)
                else:
                    qtypes = [query_o[3]]
                    pckt = copy.copy(packet)

                pckt['qr'] = 0
                pckt['answers'] = []
                pckt['ancount'] = 0
                pckt['nslist'] = []
                pckt['nscount'] = 0
                pckt['additional'] = []
                pckt['arcount'] = 0
                for qtype in qtypes:
                    if self.prefix:
                        query = (packet, query_o[1], query_o[2],
                                 0)
                    else:
                        query = (packet, query_o[1], query_o[2],
                                 qtype)

                    self.query_id = (self.query_id % 65535) + 1
                    pckt['id'] = self.query_id
                    pckt['questions'][0][1] = qtype
                    outbuf = DNS.Serialize(pckt).get_packet()
                    self.clisock.sendto(outbuf, (self.server_ip,
                                                 self.server_port))
                    self.add_query(self.server_ip,
                                   self.server_port,
                                   self.query_id, query)

                packet['questions'][0][1] = query_o[3]

            if send_reply:
                outbuf = DNS.Serialize(packet).get_packet()
                self.servsock.sendto(outbuf, (query_o[1],
                                              query_o[2]))

    def mainloop(self, unused_args):
        """HIP DNS proxy main loop."""
        logging.info('Dns proxy for HIP started')

        self.parameter_defaults()

        # Default virtual interface and address for dnsproxy to
        # avoid problems with other dns forwarders (e.g. dnsmasq)
        os.system('ifconfig lo:53 %s' % (self.bind_ip,))

        self.servsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.servsock.bind((self.bind_ip, self.bind_port))
        except socket.error:
            logging.error('Port %d already in use. See HOWTO.',
                          self.bind_port)
            return

        self.servsock.settimeout(self.app_timeout)

        self.hosts = []
        if self.hostsnames:
            for hostsname in self.hostsnames:
                self.hosts.append(hosts.Hosts(hostsname))
        else:
            if os.path.exists(self.hiphosts):
                self.hosts.append(hosts.Hosts(self.hiphosts))

        if os.path.exists(DEFAULT_HOSTS):
            self.hosts.append(hosts.Hosts(DEFAULT_HOSTS))

        self.write_local_hits_to_hosts()

        util.init_wantdown()  # Initialize signal handler for shutdown
        util.init_hup()  # Initialize signal handler for reload

        while not util.wantdown():
            self.resolvconf.parse()

            if self.server_ip is None:
                self.server_ip = self.resolvconf.nameserver

            if util.wanthup():
                logging.info('Received SIGHUP. Picking new upstream server')
                self.server_ip = self.resolvconf.nameserver
                util.wanthup(False)

            logging.info('Connecting to upstream DNS server %s ...',
                         self.server_ip)
            if ':' not in self.server_ip:
                server_family = socket.AF_INET
            else:
                server_family = socket.AF_INET6

            self.clisock = socket.socket(server_family, socket.SOCK_DGRAM)
            self.clisock.settimeout(self.dns_timeout)
            try:
                self.clisock.connect((self.server_ip, self.server_port))
                self.connected = True
                logging.debug('... connected!')
                self.resolvconf.nameserver = self.bind_ip
            except socket.error:
                logging.error('Connecting to upstream DNS server failed!')
                time.sleep(3)
                self.connected = False

            while self.connected and (not util.wantdown()) and (
                not util.wanthup()):
                try:
                    self.hosts_recheck()

                    if self.connected:
                        rlist, _, _ = select.select([self.servsock,
                                                     self.clisock],
                                                    [], [], 5.0)
                    else:
                        rlist, _, _ = select.select([self.servsock],
                                                    [], [], 5.0)

                    self.clean_queries()
                    if self.servsock in rlist:
                        payload, sender = self.servsock.recvfrom(2048)
                        packet = DNS.DeSerialize(payload).get_dict()
                        self.handle_query(packet, sender)

                    if self.connected and self.clisock in rlist:
                        payload, sender = self.clisock.recvfrom(2048)
                        logging.info('Packet from DNS server %d bytes from %s',
                                     len(payload), sender)
                        packet = DNS.DeSerialize(payload).get_dict()
                        self.handle_response(packet, sender)
                except (select.error, OSError), exc:
                    if exc[0] == errno.EINTR:
                        pass
                    else:
                        logging.exception('Exception:')
                except socket.error, exc:
                    logging.info('Connection to upstream DNS server lost')
                    self.connected = False

        logging.info('Wants down')
        self.resolvconf.restore()

if __name__ == '__main__':
    import doctest
    doctest.testmod(raise_on_error=True)
