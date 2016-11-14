from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, datetime

USING_PYTHON2 = True if sys.version_info < (3, 0) else False

if USING_PYTHON2:
    from StringIO import StringIO
    from repr import Repr
    str = unicode # noqa
    from backports.statistics import median
    from backports.functools_lru_cache import lru_cache
    from backports.shutil_get_terminal_size import get_terminal_size
    import subprocess32 as subprocess
    def timestamp(dt):
        if dt.tzinfo is None:
            from time import mktime
            return mktime((dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, -1, -1, -1)) + dt.microsecond / 1e6
        else:
            from dateutil.tz import tzutc
            return (dt - datetime.datetime(1970, 1, 1, tzinfo=tzutc())).total_seconds()
else:
    from io import StringIO
    from reprlib import Repr
    str = str
    from statistics import median
    from functools import lru_cache
    from shutil import get_terminal_size
    import subprocess
    timestamp = datetime.datetime.timestamp
