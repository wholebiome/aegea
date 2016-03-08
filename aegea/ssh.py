import os, sys, argparse, subprocess
import boto3
from . import register_parser

def ssh(args):
    ec2 = boto3.resource("ec2")
    prefix, at, name = args.name.rpartition("@")
    if not name.startswith("i-"):
        try:
            desc = ec2.meta.client.describe_instances(Filters=[dict(Name="tag:Name", Values=[name])])
            name = desc["Reservations"][0]["Instances"][0]["InstanceId"]
        except IndexError:
            raise Exception('Could not resolve "{}" to a known instance'.format(name))
    hostname = ec2.Instance(name).public_dns_name
    ssh_args = ['ssh', prefix + at + hostname] + args.ssh_args
    os.execvp("ssh", ssh_args)

parser = register_parser(ssh, help='Connect to an instance')
parser.add_argument('name')
parser.add_argument('ssh_args', nargs=argparse.REMAINDER)
