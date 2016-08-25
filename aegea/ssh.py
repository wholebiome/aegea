import os, sys, argparse, subprocess

from . import register_parser
from .util.aws import resolve_instance_id
from .util.crypto import add_ssh_host_key_to_known_hosts

def ssh(args):
    from .util.aws.resources import ec2
    prefix, at, name = args.name.rpartition("@")
    instance = ec2.Instance(resolve_instance_id(name))
    tags = {tag["Key"]: tag["Value"] for tag in instance.tags or []}
    ssh_host_key = tags.get("SSHHostPublicKeyPart1", "") + tags.get("SSHHostPublicKeyPart2", "")
    if ssh_host_key:
        # FIXME: this results in duplicates.
        # Use paramiko to detect if the key is already listed and not insert it then (or only insert if different)
        add_ssh_host_key_to_known_hosts(instance.public_dns_name + " " + ssh_host_key + "\n")
    ssh_args = ["ssh", prefix + at + instance.public_dns_name] + args.ssh_args
    os.execvp("ssh", ssh_args)

parser = register_parser(ssh, help="Connect to an instance")
parser.add_argument("name")
parser.add_argument("ssh_args", nargs=argparse.REMAINDER)
