from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys

USING_PYTHON2 = True if sys.version_info < (3, 0) else False

if USING_PYTHON2:
    from StringIO import StringIO
else:
    from io import StringIO
