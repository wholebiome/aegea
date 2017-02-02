"""
Connect to an EC2 instance via SSH, by name or instance ID.

Security groups, network ACLs, interfaces, VPC routing tables, VPC
Internet Gateways, and internal firewalls for the instance must be
configured to allow SSH connections.

To facilitate SSH connections, ``aegea ssh`` resolves instance names
to public DNS names assigned by AWS, and securely retrieves SSH host
public keys from instance metadata before connecting. This avoids both
the prompt to save the instance public key and the resulting transient
MITM vulnerability.
"""

import os, sys, argparse, subprocess

from . import register_parser
from .util.aws import resolve_instance_id, resources
from .util.crypto import add_ssh_host_key_to_known_hosts
from .util.printing import BOLD
from .util.exceptions import AegeaException

def ssh(args):
    prefix, at, name = args.name.rpartition("@")
    instance = resources.ec2.Instance(resolve_instance_id(name))
    if not instance.public_dns_name:
        msg = "Unable to resolve public DNS name for {} (state: {})"
        raise AegeaException(msg.format(instance, getattr(instance, "state", {}).get("Name")))
    tags = {tag["Key"]: tag["Value"] for tag in instance.tags or []}
    ssh_host_key = tags.get("SSHHostPublicKeyPart1", "") + tags.get("SSHHostPublicKeyPart2", "")
    if ssh_host_key:
        # FIXME: this results in duplicates.
        # Use paramiko to detect if the key is already listed and not insert it then (or only insert if different)
        add_ssh_host_key_to_known_hosts(instance.public_dns_name + " " + ssh_host_key + "\n")
    ssh_args = ["ssh", prefix + at + instance.public_dns_name] + args.ssh_args
    os.execvp("ssh", ssh_args)

parser = register_parser(ssh, help="Connect to an EC2 instance", description=__doc__,
                         formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("name")
parser.add_argument("ssh_args", nargs=argparse.REMAINDER,
                    help="Arguments to pass to ssh; please see " + BOLD("man ssh") + " for details")
