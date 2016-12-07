from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys

from .ls import filter_and_tabulate, register_filtering_parser
from .util.aws import ARN, resolve_instance_id, resources, clients
from .util.printing import format_table, page_output, get_field, get_cell, tabulate, GREEN, BLUE

def buckets(args):
    """
    List S3 buckets. See also "aws s3 ls". Use "aws s3 ls NAME" to list bucket contents.
    """
    page_output(filter_and_tabulate(resources.s3.buckets, args))

parser = register_filtering_parser(buckets)
