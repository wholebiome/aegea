import os, sys, argparse, subprocess
import boto3

from . import register_parser
from .util.aws import resolve_instance_id

def ssh(args):
    ec2 = boto3.resource("ec2")
    prefix, at, name = args.name.rpartition("@")
    instance_id = resolve_instance_id(name)
    hostname = ec2.Instance(instance_id).public_dns_name
    ssh_args = ['ssh', prefix + at + hostname] + args.ssh_args
    os.execvp("ssh", ssh_args)

parser = register_parser(ssh, help='Connect to an instance')
parser.add_argument('name')
parser.add_argument('ssh_args', nargs=argparse.REMAINDER)
