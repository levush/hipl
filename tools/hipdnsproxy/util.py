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

"""Utility functions for hipdnsproxy."""

import logging
import os
import re
import signal
import struct
import sys

__FLAGS = {'down': False, 'hup': False}


class Random:
    """Random numbers based on /dev/urandom, suitable for cryptography.

    The documentation of stdlib module random specifically states:
        "However, being completely deterministic, it is not suitable for all
        purposes, and is completely unsuitable for cryptographic purposes."
    """
    # pylint: disable=R0903
    rfile = file('/dev/urandom', 'rb')

    def __init__(self):
        return

    def random(self):
        """Return a random number between 0 and 1."""
        buf = self.rfile.read(4)
        rval = struct.unpack('I', buf)[0]
        return float(rval) / (1L << 32)


def rand(random=Random()):
    """Return a random number between 0 and 1.

    >>> 0 < rand() < 1
    True
    """
    return random.random()


def sighandler(signum, unused_frame):
    """A signal handler that toggles flags about received signals."""
    if signum in (signal.SIGTERM, signal.SIGINT):
        __FLAGS['down'] = True
    if signum == signal.SIGHUP:
        __FLAGS['hup'] = True


def init_wantdown():
    """Hook signal handler to SIGTERM."""
    signal.signal(signal.SIGTERM, sighandler)
    signal.signal(signal.SIGINT, sighandler)


def init_hup():
    """Hook signal handler to SIGHUP."""
    signal.signal(signal.SIGHUP, sighandler)


def wantdown():
    """Check if SIGINT or SIGTERM has been received."""
    return __FLAGS['down']


def wanthup(reset=None):
    """Check if SIGHUP has been received."""
    previous = __FLAGS['hup']

    if reset is not None:
        __FLAGS['hup'] = reset

    return previous

TMULT = (
    (re.compile('^(?P<tval>-?\d+(\.\d*))(s|)$', re.I), float, 1),
    (re.compile('^(?P<tval>-?\d+)(s|)$', re.I), int, 1),
    (re.compile('^(?P<tval>-?\d+(\.\d*))m$', re.I), float, 60),
    (re.compile('^(?P<tval>-?\d+)m$', re.I), int, 60),
    (re.compile('^(?P<tval>-?\d+(\.\d*))h$', re.I), float, 60 * 60),
    (re.compile('^(?P<tval>-?\d+)h$', re.I), int, 60 * 60),
    (re.compile('^(?P<tval>-?\d+(\.\d*))d$', re.I), float, 60 * 60 * 24),
    (re.compile('^(?P<tval>-?\d+)d$', re.I), int, 60 * 60 * 24),
    )


class TimeSpecError(Exception):
    """Raised when There's an error with a time specification."""
    pass


def timespec(spec, default=None):
    """Return human readable time specification converted to seconds.

    >>> timespec('1m')
    60

    >>> timespec('1.5m')
    90.0

    >>> timespec('0.5h')
    1800.0

    >>> timespec('0.1d')
    8640.0
    """
    for tre, fun, tmul in TMULT:
        match = tre.match(spec)
        if match:
            return fun(match.group('tval')) * tmul
    if not default:
        raise TimeSpecError('Invalid timespec: %s' % spec)
    return default


def verbosetime(secs):
    """Format seconds as days, hours, minutes and secs.

    >>> verbosetime(0.5)
    '0.500s'

    >>> verbosetime(30)
    '30s'

    >>> verbosetime(90)
    '1m30s'

    >>> verbosetime(3690)
    '1h01m30s'

    >>> verbosetime(91000)
    '1d01h16m40s'
    """
    if secs < 1.0:
        return '%.3fs' % secs
    if secs < 60:
        return '%ds' % secs
    secs = int(secs)
    if secs < 60 * 60:
        mins, secs = divmod(secs, 60)
        return '%dm%02ds' % (mins, secs)
    if secs < 24 * 60 * 60:
        hours, secs = divmod(secs, 60 * 60)
        mins, secs = divmod(secs, 60)
        return '%dh%02dm%02ds' % (hours, mins, secs)
    days, secs = divmod(secs, 24 * 60 * 60)
    hours, secs = divmod(secs, 60 * 60)
    mins, secs = divmod(secs, 60)
    return '%dd%02dh%02dm%02ds' % (days, hours, mins, secs)


def log2syslog():
    """Configure logging to send messages to syslog."""
    loghandler = logging.handlers.SysLogHandler(address='/dev/log',
        facility=logging.handlers.SysLogHandler.LOG_DAEMON)
    loghandler.setFormatter(logging.Formatter(
        'hipdnsproxy[%(process)s] %(levelname)-8s %(message)s'))
    logging.getLogger().addHandler(loghandler)


def daemonize():
    """Daemonize current process."""
    pid = os.fork()

    if pid:
        sys.exit(0)

    if 'DEBCONF_REDIR' in os.environ:
        # debconf redirects stdout to fd 3 so it can use stdin & stdout
        os.close(3)

    os.chdir('/')
    os.setsid()
    os.umask(0)

    pid = os.fork()

    if pid:
        sys.exit(0)

    log2syslog()

    sys.stdout.flush()
    sys.stderr.flush()

    stdin = file(os.devnull, 'r')
    stdout = file(os.devnull, 'a+')
    stderr = file(os.devnull, 'a+', 0)

    os.dup2(stdin.fileno(), sys.stdin.fileno())
    os.dup2(stdout.fileno(), sys.stdout.fileno())
    os.dup2(stderr.fileno(), sys.stderr.fileno())

    return True


if __name__ == '__main__':
    import doctest
    doctest.testmod(raise_on_error=True)
