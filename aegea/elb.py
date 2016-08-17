"""
Manage AWS EC2 Elastic Load Balancers (ELBs).
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse

from .ls import register_parser, register_listing_parser
from .util.exceptions import AegeaException
from .util import Timestamp, paginate
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.aws import ARN, resources, clients, resolve_instance_id, resolve_security_group, get_elb_dns_aliases, DNSZone

def elb(args):
    elb_parser.print_help()

elb_parser = register_parser(elb, help='Manage Elastic Load Balancers', description=__doc__,
                             formatter_class=argparse.RawTextHelpFormatter)

def ls(args):
    table = []
    dns_aliases = get_elb_dns_aliases()
    for row in paginate(clients.elb.get_paginator('describe_load_balancers')):
        row["alias"] = dns_aliases.get(row["DNSName"])
        instances = clients.elb.describe_instance_health(LoadBalancerName=row["LoadBalancerName"])["InstanceStates"]
        table.extend([dict(row, **instance) for instance in instances] if instances else [row])
    page_output(tabulate(table, args))

parser = register_listing_parser(ls, parent=elb_parser)

def register(args):
    instances = [dict(InstanceId=i) for i in args.instances]
    res = clients.elb.register_instances_with_load_balancer(LoadBalancerName=args.elb_name, Instances=instances)
    return dict(registered=args.instances, current=[i["InstanceId"] for i in res["Instances"]])

parser = register_parser(register, parent=elb_parser, help="Add EC2 instances to an ELB")
parser.add_argument("elb_name")
parser.add_argument("instances", nargs="+", type=resolve_instance_id)

def deregister(args):
    instances = [dict(InstanceId=i) for i in args.instances]
    res = clients.elb.deregister_instances_from_load_balancer(LoadBalancerName=args.elb_name, Instances=instances)
    return dict(deregistered=args.instances, current=[i["InstanceId"] for i in res["Instances"]])

parser = register_parser(deregister, parent=elb_parser, help="Remove EC2 instances from an ELB")
parser.add_argument("elb_name")
parser.add_argument("instances", nargs="+", type=resolve_instance_id)

def replace(args):
    result = register(args)
    old_instances = set(result["current"]) - set(result["registered"])
    if old_instances:
        args.instances = list(old_instances)
        result.update(deregister(args))
    return result

parser = register_parser(replace, parent=elb_parser, help="Replace all EC2 instances in an ELB with the ones given")
parser.add_argument("elb_name")
parser.add_argument("instances", nargs="+", type=resolve_instance_id)

def create(args):
    for zone in paginate(clients.route53.get_paginator('list_hosted_zones')):
        if args.dns_alias.endswith("." + zone["Name"].rstrip(".")):
            break
    else:
        raise AegeaException("Unable to find Route53 DNS zone for {}".format(args.dns_alias))
    for cert in paginate(clients.acm.get_paginator('list_certificates')):
        if cert["DomainName"] in (args.dns_alias, ".".join(["*"] + args.dns_alias.split(".")[1:])):
            break
    else:
        raise AegeaException("Unable to find ACM certificate for {}".format(args.dns_alias))
    azs = [az["ZoneName"] for az in clients.ec2.describe_availability_zones()["AvailabilityZones"]]
    listener = dict(Protocol="https",
                    LoadBalancerPort=443,
                    SSLCertificateId=cert["CertificateArn"],
                    InstanceProtocol="http",
                    InstancePort=args.instance_port or 80)
    elb = clients.elb.create_load_balancer(LoadBalancerName=args.elb_name,
                                           Listeners=[listener],
                                           AvailabilityZones=azs,
                                           SecurityGroups=[sg.id for sg in args.security_groups])
    register(args)
    DNSZone(zone["Name"]).update(args.dns_alias.replace("." + zone["Name"].rstrip("."), ""), elb["DNSName"])
    return dict(elb_name=args.elb_name, dns_name=elb["DNSName"], dns_alias=args.dns_alias)

parser = register_parser(create, parent=elb_parser, help="Create a new ELB")
parser.add_argument("elb_name")
parser.add_argument("instances", nargs="+", type=resolve_instance_id)
parser.add_argument("--security-groups", nargs="+", type=resolve_security_group, required=True)
parser.add_argument("--dns-alias", required=True)
parser.add_argument("--instance-port", type=int)
