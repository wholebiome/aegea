from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys
from datetime import datetime

import boto3

from . import register_parser
from .util.printing import format_table, page_output

def top(args):
    table = []
    columns = ["Region", "Instances", "AMIs"]
    for region in boto3.client("ec2").describe_regions()["Regions"]:
        session = boto3.session.Session(region_name=region["RegionName"])
        num_instances = len(list(session.resource("ec2").instances.all()))
        num_amis = len(list(session.resource("ec2").images.filter(Owners=["self"])))
        table.append([region["RegionName"], num_instances, num_amis])
    page_output(format_table(table, column_names=columns, max_col_width=args.max_col_width))

parser = register_parser(top, help='Show an overview of AWS resources per region')
