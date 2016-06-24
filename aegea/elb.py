"""
Manage AWS EC2 Elastic Load Balancers (ELBs).
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, getpass
from datetime import datetime

from . import register_parser
from .util import Timestamp, paginate
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.aws import ARN, resources, clients, resolve_instance_id

def elb(args):
    elb_parser.print_help()

elb_parser = register_parser(elb, help='Manage Elastic Load Balancers', description=__doc__,
                             formatter_class=argparse.RawTextHelpFormatter)

def ls(args):
    #dualstack.akita-1629521448.us-west-2.elb.amazonaws.com.
    table, dns_aliases = [], {}
    for zone in paginate(clients.route53.get_paginator('list_hosted_zones')):
        for rrs in paginate(clients.route53.get_paginator('list_resource_record_sets'), HostedZoneId=zone["Id"]):
            for record in rrs.get("ResourceRecords", [rrs.get("AliasTarget", {})]):
                value = record.get("Value", record.get("DNSName"))
                if value.endswith("elb.amazonaws.com."):
                    dns_aliases[value.rstrip(".").replace("dualstack.", "")] = rrs["Name"]
    for row in paginate(clients.elb.get_paginator('describe_load_balancers')):
        row["alias"] = dns_aliases.get(row["DNSName"])
        table.append(row)
    page_output(tabulate(table, args))

parser = register_parser(ls, parent=elb_parser)

def register(args):
    instances = [dict(InstanceId=resolve_instance_id(i)) for i in args.instances]
    clients.elb.register_instances_with_load_balancer(LoadBalancerName=args.elb_name, Instances=instances)

parser = register_parser(register, parent=elb_parser, help="Add EC2 instances to an ELB")
parser.add_argument("elb_name")
parser.add_argument("instances", nargs="+")

def deregister(args):
    instances = [dict(InstanceId=resolve_instance_id(i)) for i in args.instances]
    clients.elb.deregister_instances_from_load_balancer(LoadBalancerName=args.elb_name, Instances=instances)

parser = register_parser(deregister, parent=elb_parser, help="Remove EC2 instances from an ELB")
parser.add_argument("elb_name")
parser.add_argument("instances", nargs="+")

def replace(args):
    register(args)
    elb_desc = clients.elb.describe_load_balancers(LoadBalancerNames=[args.elb_name])["LoadBalancerDescriptions"][0]
    old_instances = set(i["InstanceId"] for i in elb_desc["Instances"])
    new_instances = set(resolve_instance_id(i) for i in args.instances)
    args.instances = old_instances - new_instances
    if args.instances:
        deregister(args)

parser = register_parser(replace, parent=elb_parser, help="Replace all EC2 instances in an ELB with the ones given")
parser.add_argument("elb_name")
parser.add_argument("instances", nargs="+")
