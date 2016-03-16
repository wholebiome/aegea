from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys
import boto3
from . import register_parser, config
from .util.aws import DNSZone

def resolve_instance_ids(input_names):
    ec2 = boto3.resource("ec2")
    ids = [n for n in input_names if n.startswith("i-")]
    names = [n for n in input_names if not n.startswith("i-")]
    if names:
        descriptions = ec2.meta.client.describe_instances(Filters=[dict(Name="tag:Name", Values=names)])
        for reservation in descriptions["Reservations"]:
            for instance in reservation["Instances"]:
                ids.append(instance["InstanceId"])
    if len(ids) != len(input_names):
        raise Exception("Unable to resolve one or more of the instance names")
    return ec2, ids, names

def start(args):
    ec2, ids, names = resolve_instance_ids(args.names)
    ec2.meta.client.start_instances(InstanceIds=ids)

def stop(args):
    ec2, ids, names = resolve_instance_ids(args.names)
    ec2.meta.client.stop_instances(InstanceIds=ids)

def reboot(args):
    ec2, ids, names = resolve_instance_ids(args.names)
    ec2.meta.client.reboot_instances(InstanceIds=ids)

def terminate(args):
    dns_zone = DNSZone(config.dns.private_zone)
    ec2, ids, names = resolve_instance_ids(args.names)
    ec2.meta.client.terminate_instances(InstanceIds=ids)
    for name in names:
        # FIXME: when terminating by id, look up and delete DNS name
        dns_zone.delete(name)

for action in (start, stop, reboot, terminate):
    parser = register_parser(action, help='{} EC2 instances'.format(action.__name__.capitalize()))
    parser.add_argument("names", nargs="+")
