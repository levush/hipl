#! /usr/bin/env python

# Copyright (c) 2012-2013 Aalto University and RWTH Aachen University.
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

"""Handler for resolv.conf, including resolvconf(8)."""

import collections
import errno
import logging
import os
import subprocess
import tempfile
import time


class FragmentFile(object):
    """File-like object for reading through a virtual file made of fragments.

    Also respects fragment ordering."""
    def __init__(self, fragments):
        self.fragments = fragments
        self.current = None
        self.nextfragment()

    def __iter__(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, trackeback):
        pass

    def nextfragment(self):
        """Advance current fragment. Returns True when successful."""
        if self.fragments:
            fragment = self.fragments.pop(0)
            retries = 3
            while retries > 0:
                try:
                    self.current = open(fragment, 'rb')
                    return True
                except IOError, ioe:
                    if ioe.errno != errno.ENOENT:
                        raise
                    time.sleep(0.1)
                retries -= 1
        self.current = None
        return False

    def next(self):
        """Returns next line in virtual file."""
        if self.current is None:
            raise StopIteration()

        try:
            return self.current.next()
        except StopIteration, sie:
            if self.nextfragment():
                return self.next()
            else:
                raise sie


class ResolvConf(object):
    """Handle resolv.conf."""
    DEFAULT_BIND_ADDR = '127.0.0.53'
    INTERFACE = 'lo.hipdnsproxy'
    RESOLV_CONF = '/etc/resolv.conf'
    RESOLVCONF = '/sbin/resolvconf'
    LIST_RECORDS = '/lib/resolvconf/list-records'
    FRAGMENT_DIR = ['/run/resolvconf/interface',
                    '/var/run/resolvconf/interface']

    def __init__(self, myid=None):
        if myid is None:
            myid = os.getpid()
        self.myid = myid

        self.path = ResolvConf.RESOLV_CONF

        # is resolvconf(8) using hardcoded location ?
        if (os.path.exists(ResolvConf.RESOLVCONF) and
            os.path.islink(self.path)):
            self.using_resolvconf = True
        else:
            self.using_resolvconf = False

        self.mtime = None
        self.config = None

        if self.using_resolvconf and isinstance(ResolvConf.FRAGMENT_DIR, list):
            # pylint: disable-msg=W0141
            ResolvConf.FRAGMENT_DIR = filter(os.path.exists,
                                             ResolvConf.FRAGMENT_DIR)[0]

    def realpath(self):
        """Return the real path to the actual resolv.conf."""
        return os.path.realpath(self.path)

    def is_up2date(self):
        """Have we read resolv.conf since it last changed?"""
        if (self.mtime is None or
            self.mtime < os.stat(self.realpath()).st_mtime):
            return False

        return True

    @classmethod
    def fragments(cls):
        """Return list of resolvconf fragments."""
        retries = 3
        while retries > 0:
            try:
                proc = subprocess.Popen([ResolvConf.LIST_RECORDS],
                        cwd=ResolvConf.FRAGMENT_DIR, stdout=subprocess.PIPE)

                out = proc.stdout.readlines()
                proc.communicate()
                proc.wait()

                frags = [x.strip() for x in out]

                return [os.path.join(ResolvConf.FRAGMENT_DIR, x)
                        for x in frags]
            except IOError, ioe:
                if ioe.errno != errno.EINTR:
                    raise
                retries -= 1

    @classmethod
    def resolvconf_add(cls, ifile):
        """Pass new fragment to resolvconf(8)."""
        proc = subprocess.Popen([ResolvConf.RESOLVCONF, '-a',
                                 ResolvConf.INTERFACE], stdin=ifile)
        proc.communicate()
        proc.wait()

    @classmethod
    def resolvconf_delete(cls):
        """Call resolvconf(8) to remove fragment."""
        subprocess.check_call([ResolvConf.RESOLVCONF, '-d',
                               ResolvConf.INTERFACE])

    def backup_name(self):
        """Return name of backup file."""
        return '%s-%s' % (self.realpath(), self.myid)

    def backup(self):
        """Backup current resolv.conf."""
        if not self.using_resolvconf:
            if os.path.exists(self.backup_name()):
                logging.error('Skipping backup, file already exists: %s',
                        self.backup_name())
                return
            os.link(self.realpath(), self.backup_name())

    def restore(self):
        """Restore resolv.conf to original state."""
        if self.using_resolvconf:
            self.resolvconf_delete()
        else:
            if not os.path.exists(self.backup_name()):
                logging.error('No backup to restore: %s', self.backup_name())
                return
            os.rename(self.backup_name(), self.realpath())

    def parse(self):
        """Parse resolv.conf until we have an up to date representation."""
        done = False
        while not done:
            self.mtime = os.stat(self.realpath()).st_mtime

            if self.using_resolvconf:
                with FragmentFile(self.fragments()) as ifile:
                    self.parse_file(ifile)
            else:
                with file(self.path, 'rb') as ifile:
                    self.parse_file(ifile)

            done = self.is_up2date()

    def parse_file(self, ifile):
        """Parse resolv.conf from a file object."""
        config = collections.defaultdict(list)

        for line in ifile:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue

            parts = line.split()
            keyword = parts.pop(0)

            if keyword == 'domain':
                config[keyword] = parts[0]
            elif keyword == 'search':
                config[keyword] = parts
            elif keyword == 'nameserver':
                if parts[0] == ResolvConf.DEFAULT_BIND_ADDR:
                    continue
                config[keyword].append(parts[0])
            elif keyword in ['sortlist', 'options']:
                config[keyword].extend(parts)
            else:
                logging.error('Unrecognized keyword "%s" in resolv.conf',
                              keyword)

        self.config = config

    def write_file(self, ofile):
        """Write out config to file."""
        for keyword, value in self.config.iteritems():
            if keyword == 'domain':
                ofile.write('%s %s\n' % (keyword, value))
            elif keyword in ['search', 'sortlist', 'options']:
                ofile.write('%s %s\n' % (keyword, ' '.join(value)))
            elif keyword == 'nameserver':
                for val in value:
                    ofile.write('%s %s\n' % (keyword, val))
            else:
                logging.error('Unrecognized keyword "%s" in config.', keyword)

    def write(self, config=None):
        """Write out config."""
        if config is not None:
            self.config.update(config)

        if self.using_resolvconf:
            with tempfile.TemporaryFile() as ofile:
                self.write_file(ofile)
                ofile.seek(0)
                self.resolvconf_add(ofile)
        else:
            self.backup()
            with file('%s-new' % self.realpath(), 'wb') as ofile:
                self.write_file(ofile)
            os.rename('%s-new' % self.realpath(), self.realpath())

        self.mtime = os.stat(self.realpath()).st_mtime

    @property
    def nameserver(self):
        """Return a nameserver address from resolv.conf."""
        if 'nameserver' in self.config:
            nameservers = [x for x in self.config['nameserver'] if x !=
                           ResolvConf.DEFAULT_BIND_ADDR]
            if nameservers:
                return nameservers[0]
        return '8.8.8.8'  # Google Public DNS, fallback

    @nameserver.setter
    def nameserver(self, nameserver):
        """Set a new value for nameserver."""
        self.config['nameserver'] = [nameserver]
        self.write()

    @property
    def search_list(self):
        """Return normalized resolver search list."""
        if self.config is None:
            return []

        if 'search' not in self.config:
            if 'domain' in self.config:
                return [self.config['domain'].lower()]
            return []

        return [x.lower() for x in self.config['search']]
