from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys
import boto3

from .ls import register_listing_parser
from .util.printing import page_output, tabulate
from .util.aws import ARN, resolve_instance_id

def alarms(args):
    page_output(tabulate(boto3.resource("cloudwatch").alarms.all(), args))

parser = register_listing_parser(alarms, help='List CloudWatch alarms')
