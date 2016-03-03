from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys
import boto3

from . import register_parser, logger
from .util.aws import get_user_data, ensure_vpc, ensure_subnet, ensure_ingress_rule, ensure_security_group, DNSZone
from .util.crypto import new_ssh_key, add_ssh_host_key_to_known_hosts, ensure_ssh_key

def set_tags(resource, **tags):
    resource.create_tags(Tags=[dict(Key=k, Value=v) for k, v in tags.items()])

def get_startup_commands(args):
    return [
        "hostnamectl set-hostname " + args.hostname
    ]

def launch(args):
    ec2 = boto3.resource("ec2")
    ensure_ssh_key(args.ssh_key_name)
    assert not args.hostname.startswith("i-")
    if args.ami is None:
        amis = sorted(ec2.images.filter(Owners=["self"]), key=lambda ami: ami.creation_date)
        args.ami = amis[-1].id
    vpc = ensure_vpc()
    subnet = ensure_subnet(vpc)
    security_group = ensure_security_group("test", vpc)
    ssh_host_key = new_ssh_key()
    instances = subnet.create_instances(ImageId=args.ami,
                                        KeyName=args.ssh_key_name,
                                        SecurityGroupIds=[security_group.id],
                                        InstanceType=args.instance_type,
                                        #IamInstanceProfile=dict(Arn=instance_profile.arn),
                                        UserData=get_user_data(host_key=ssh_host_key, commands=get_startup_commands(args)),
                                        MinCount=1,
                                        MaxCount=1)
    instance = instances[0]
    instance.wait_until_running()
    set_tags(instance, Name=args.hostname)
    DNSZone("FIXME").update(args.hostname, instance.private_dns_name)
    logger.info("Launched %s in %s", instance, subnet)
    add_ssh_host_key_to_known_hosts(instance.public_dns_name, ssh_host_key)

parser = register_parser(launch, help='Launch a new EC2 instance')
parser.add_argument('hostname')
parser.add_argument('--instance-type', '-t', default="t2.micro")
parser.add_argument("--ssh-key-name", default="gaia2")
parser.add_argument('--ami', type=str)
