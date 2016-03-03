"""
Aegea: Amazon Web Services Operator Interface
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import argparse, logging

logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser(description=__doc__)
parser.set_defaults(entry_point=lambda args: parser.print_help())
subparsers = parser.add_subparsers(title='commands')

def register_parser(function, **kwargs):
    parser = subparsers.add_parser(function.__name__, **kwargs)
    parser.set_defaults(entry_point=function)
    return parser
