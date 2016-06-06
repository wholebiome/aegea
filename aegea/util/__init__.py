from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, re, socket, errno, time
from datetime import datetime
from dateutil.parser import parse as dateutil_parse
from dateutil.relativedelta import relativedelta
from .printing import GREEN
from .compat import Repr, str
from .. import logger

def wait_for_port(host, port, timeout=600, print_progress=True):
    if print_progress:
        sys.stderr.write("Waiting for {}:{}...".format(host, port))
        sys.stderr.flush()
    start_time = time.time()
    while True:
        try:
            socket.socket().connect((host, port))
            if print_progress:
                sys.stderr.write(GREEN("OK") + "\n")
            return
        except Exception:
            time.sleep(1)
            if print_progress:
                sys.stderr.write(".")
                sys.stderr.flush()
            if time.time() - start_time > timeout:
                raise

def validate_hostname(hostname):
    if len(hostname) > 255:
        raise Exception("Hostname {} is longer than 255 characters".format(hostname))
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    if not all(allowed.match(x) for x in hostname.split(".")):
        raise Exception("Hostname {} is not RFC 1123 compliant".format(hostname))

class VerboseRepr:
    def __repr__(self):
        return "<{module}.{classname} object at 0x{mem_loc:x}: {dict}>".format(
            module=self.__module__,
            classname=self.__class__.__name__,
            mem_loc=id(self),
            dict=Repr().repr(self.__dict__)
        )

def natural_sort(i):
    return sorted(i, key=lambda s: [int(t) if t.isdigit() else t.lower() for t in re.split('(\d+)', s)])

def parse_time_input(t):
    """
    Integer inputs are interpreted as seconds since the epoch. Suffixes (s, m, h, d, w) are supported. Negative inputs
    (e.g. -5m) are interpreted as relative to the current date. Other inputs (e.g. 2020-01-01, 15:20) are parsed using
    the dateutil parser.
    """
    if not isinstance(t, (str, bytes)):
        raise ValueError("Expected a string, but got {}".format(type(t)))
    if t.isdigit():
        return datetime.utcfromtimestamp(int(t)/1000)
    try:
        return dateutil_parse(t)
    except (ValueError, OverflowError, AssertionError):
        units = {"weeks", "days", "hours", "minutes", "seconds"}
        diffs = {u: float(t[:-1]) for u in units if u.startswith(t[-1])}
        if len(diffs) != 1:
            raise ValueError('Could not parse "{}" as a timestamp or time delta'.format(t))
        return datetime.utcnow().replace(microsecond=0) + relativedelta(**diffs)
