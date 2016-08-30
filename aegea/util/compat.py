from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys

USING_PYTHON2 = True if sys.version_info < (3, 0) else False

if USING_PYTHON2:
    from StringIO import StringIO
    from repr import Repr
    str = unicode # noqa
    from backports.statistics import median
    from backports.functools_lru_cache import lru_cache
else:
    from io import StringIO
    from reprlib import Repr
    str = str
    from statistics import median
    from functools import lru_cache
