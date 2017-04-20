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

# pylint: disable=C0103,C0111,R0904

import resolvconf
import StringIO
import unittest

VALID_RESOLV_CONF = '''
# resolv.conf
domain example.com
search example.com
nameserver 8.8.4.4
nameserver 8.8.8.8
'''

INVALID_RESOLV_CONF = '''
 # foo
nameserver barbaz
this should be interesting
'''


class ResolvConfTest(unittest.TestCase):
    def setUp(self):
        resolvconf.ResolvConf.resolvconf_delete = classmethod(lambda *x: None)

    def test_parse_valid_file(self):
        rc = resolvconf.ResolvConf()
        rc.parse_file(StringIO.StringIO(VALID_RESOLV_CONF))
        conf = rc.config
        self.assertEqual(conf['domain'], 'example.com')
        self.assertEqual(conf['search'], ['example.com'])
        self.assertEqual(conf['nameserver'], ['8.8.4.4', '8.8.8.8'])

    def dont_test_parse_invalid_file(self):
        rc = resolvconf.ResolvConf()
        conf = rc.config
        rc.parse_file(StringIO.StringIO(INVALID_RESOLV_CONF))
        # TODO: implement validation
        self.assertEqual(conf, rc.config)

    def test_search_list(self):
        rc = resolvconf.ResolvConf()
        self.assertEqual(rc.search_list, [])
        rc.config = {'domain': 'EXAMPLE.COM'}
        self.assertEqual(rc.search_list, ['example.com'])
        rc.config['search'] = ['example.net', 'example.org']
        self.assertEqual(rc.search_list, ['example.net', 'example.org'])

    def test_write_file(self):
        rc = resolvconf.ResolvConf()
        rc.resolvconf = True
        rc.config = {'domain': 'example.com',
                     'search': ['example.com', 'example.net'],
                     'nameserver': ['8.8.4.4', '8.8.8.8']}
        rc.resolvconf_add = lambda x: None
        ofile = StringIO.StringIO()
        rc.write_file(ofile)
        out = ofile.getvalue()
        self.assertTrue('domain example.com' in out)
        self.assertTrue('search example.com example.net' in out)
        self.assertTrue('nameserver 8.8.4.4' in out)
        self.assertTrue('nameserver 8.8.8.8' in out)

    def test_prop_nameserver_noconfig(self):
        rc = resolvconf.ResolvConf()
        rc.parse_file(StringIO.StringIO(''))
        self.assertEqual(rc.nameserver, '8.8.8.8')


if __name__ == '__main__':
    unittest.main()
