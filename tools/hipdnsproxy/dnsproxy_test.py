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

# pylint: disable-msg=C0111,R0903,C0103,R0904

import DNS
import dnsproxy
import logging
import os
import subprocess
import StringIO
import unittest


# Template DNS packet for used as basis of other packets in testing (rfc2929)
TEMPLATE_PACKET = {'aa': 0,  # authoritativy answer
                   'additional': [],  # additional records
                   'ancount': 0,  # answer count, len(answers)
                   'answers': [],  # answer records
                   'arcount': 0,  # additional count, len(additional)
                   'id': 0,  # Transaction id
                   'nscount': 0,  # ns count, len(nslist)
                   'nslist': [],  # NS records
                   'opcode': 0,  # 0 = query (rfc1035)
                                 # 1 = inverse query (rfc1035)
                                 # 2 = status (rfc1035)
                                 # 4 = notify (rfc1996)
                                 # 5 = update (rfc2136)
                   'qdcount': 0,  # query count, len(questions)
                   'qr': 0,  # 0 = query, 1 = response
                   'questions': [],  # questions
                   'ra': 1,  # recursion available flag
                   'rcode': 0,  # 0 = no error (rfc1035)
                                # 1 = format error (rfc1035)
                                # 2 = server failure (rfc 1035)
                                # 3 = nxdomain (rfc1035)
                                # 4 = not implemented (rfc1035)
                                # 5 = query refused (rfc1035)
                                # 6 = yxdomain (rfc2136)
                                # 7 = yxrrset (rfc2136)
                                # 8 = nxrrset (rfc2136)
                                # 9 = not authoritative (rfc2136)
                                # 10 = not in zone (rfc2136)
                                # 16 = bad tsig (rfc2845)
                                # 17 = bad key (rfc2845)
                                # 18 = bad time (rfc2845)
                                # 19 = bad tkey mode (rfc2930)
                                # 20 = bad key name (rfc2930)
                                # 21 = bad algorithm (rfc2930)
                   'rd': 0,  # recursion desired flag
                   'tc': 0,  # message truncated flag
                   'z': 0}  # no longer in use, ignore (rfc2929)
SIMPLE_RESPONSE = TEMPLATE_PACKET.copy()
SIMPLE_RESPONSE.update({'ancount': 1,
                        'answers': (('example.com', DNS.Type.A, DNS.Class.IN,
                                     60, '127.0.0.1'),),
                        'qdcount': 1,
                        'questions': (('example.com', DNS.Type.A,
                                       DNS.Class.IN),),
                        'qr': 1})

SIMPLE_QUERY = TEMPLATE_PACKET.copy()
SIMPLE_QUERY.update({'qdcount': 1,
                     'questions': (('example.com', DNS.Type.A,
                                    DNS.Class.IN),)})


HIT = '2001:1b:a9be:c6a6:34e5:8361:c07f:a990'
LSI = '1.0.0.1'


class MockSocket(object):
    def sendto(self, payload, sender):
        pass


class MockFile(object):
    def __init__(self, exc=None, payload=None):
        self.exc = exc
        self.payload = StringIO.StringIO(payload)

    def __iter__(self):
        if self.exc is not None:
            return self
        return self.payload.__iter__()

    def next(self):
        if self.exc is not None:
            raise self.exc
        raise StopIteration


class MockPopen(object):
    def __init__(self, exc=None, stdout=None, returncode=0):
        if exc is not None:
            self.stdout = MockFile(exc=exc, payload=stdout)
        else:
            self.stdout = StringIO.StringIO(stdout)

        self.returncode = returncode


class DNSProxyTest(unittest.TestCase):
    def setUp(self):
        logging.basicConfig(level=logging.DEBUG, stream=open(os.devnull, 'w'))
        self.dnsproxy = dnsproxy.DNSProxy()
        self.dnsproxy.hosts = []
        self.dnsproxy.clisock = MockSocket()
        self.dnsproxy.servsock = MockSocket()

    def test_handle_response(self):
        self.dnsproxy.add_query('127.0.0.1', 53, 0,
                                (SIMPLE_QUERY, '127.0.0.1', 53,
                                 SIMPLE_QUERY['questions'][0][1]))
        self.dnsproxy.handle_response(SIMPLE_RESPONSE, ('127.0.0.1', 53))

    def test_handle_query(self):
        self.dnsproxy.handle_query(SIMPLE_QUERY, ('127.0.0.1', 53))

    def test_is_reverse_hit_query(self):
        self.assertFalse(dnsproxy.is_reverse_hit_query('::1'))
        name = ('8.e.b.8.b.3.c.9.1.a.0.c.e.e.2.c.c.e.d.0.9.c.9.a.e.1.0.0.1.0.'
                '0.2.hit-to-ip.infrahip.net')
        self.assertTrue(dnsproxy.is_reverse_hit_query(name))

    def test_hit_to_lsi(self):
        subprocess.Popen = lambda *x, **y: MockPopen(exc=IOError('hit_to_lsi'))
        lsi = dnsproxy.hit_to_lsi(HIT)
        self.assertIsNone(lsi)

        subprocess.Popen = lambda *x, **y: MockPopen(returncode=254)
        lsi = dnsproxy.hit_to_lsi(HIT)
        self.assertIsNone(lsi)

        subprocess.Popen = lambda *x, **y: MockPopen(stdout=LSI)
        lsi = dnsproxy.hit_to_lsi(HIT)
        self.assertEqual(lsi, LSI)

    def test_lsi_to_hit(self):
        subprocess.Popen = lambda *x, **y: MockPopen(exc=IOError('lsi_to_hit'))
        hit = dnsproxy.lsi_to_hit(LSI)
        self.assertIsNone(hit)

        subprocess.Popen = lambda *x, **y: MockPopen(returncode=254)
        hit = dnsproxy.lsi_to_hit(LSI)
        self.assertIsNone(hit)

        subprocess.Popen = lambda *x, **y: MockPopen(stdout=HIT)
        hit = dnsproxy.lsi_to_hit(LSI)
        self.assertEqual(hit, HIT)

    def test_add_hit_ip_map(self):
        # pylint: disable-msg=W0613
        def check_call(*x, **y):
            raise subprocess.CalledProcessError(254, 'hipconf daemon')
        subprocess.check_call = check_call
        self.assertIsNone(dnsproxy.add_hit_ip_map(HIT, LSI))


if __name__ == '__main__':
    unittest.main()
