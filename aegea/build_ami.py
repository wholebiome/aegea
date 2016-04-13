from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json, time
from argparse import Namespace

import boto3

from . import register_parser, logger, config
from .util import AegeaSSHClient
from .util.aws import (locate_ubuntu_ami, get_user_data, ensure_vpc, ensure_subnet, ensure_ingress_rule,
                       ensure_security_group, add_tags, get_bdm, resolve_instance_id)
from .util.crypto import ensure_ssh_key, new_ssh_key, add_ssh_host_key_to_known_hosts
from .launch import launch

def get_bootstrap_files():
    manifest = []
    rootfs_skel_dir = config.build_ami.rootfs_skel
    if rootfs_skel_dir == "auto":
        rootfs_skel_dir = os.path.join(os.path.dirname(__file__), "rootfs.skel")
    if not os.path.exists(rootfs_skel_dir):
        raise Exception("rootfs_skel directory {} not found".format(rootfs_skel_dir))
    for root, dirs, files in os.walk(rootfs_skel_dir):
        for file_ in files:
            with open(os.path.join(root, file_)) as fh:
                manifest.append(dict(path=os.path.join("/", os.path.relpath(root, rootfs_skel_dir), file_),
                                     content=fh.read(),
                                     permissions=oct(os.stat(os.path.join(root, file_)).st_mode)[-3:]))
    return manifest

def get_bootstrap_commands():
    return config.build_ami.commands

def get_bootstrap_packages():
    return config.build_ami.packages

def get_ssh_key_filename(args):
    if args.ssh_key_name is None:
        try:
            args.ssh_key_name = __name__
            return ensure_ssh_key(args.ssh_key_name)
        except KeyError:
            from getpass import getuser
            from socket import gethostname
            args.ssh_key_name = __name__ + "." + getuser() + "." + gethostname()
            return ensure_ssh_key(args.ssh_key_name)
    else:
        return ensure_ssh_key(args.ssh_key_name)

def build_image(args):
    ec2 = boto3.resource("ec2")
    iam = boto3.resource("iam")
    ssh_key_filename = get_ssh_key_filename(args)
    if args.snapshot_existing_host:
        instance = ec2.Instance(resolve_instance_id(args.snapshot_existing_host))
        args.ami = instance.image_id
    else:
        args.ami = args.base_ami or locate_ubuntu_ami(region=ec2.meta.client.meta.region_name)
        args.hostname = "{}-{}".format(__name__.replace(".", "-").replace("_", "-"), int(time.time()))
        args.wait_for_ssh = True
        args.verify_ssh_key_pem_file = True
        for field in "spot spot_price duration_hours iam_role subnet availability_zone use_dns cores min_mem_per_core_gb".split():
            setattr(args, field, None)
        instance = launch(args,
                          user_data_commands=get_bootstrap_commands(),
                          user_data_packages=get_bootstrap_packages(),
                          user_data_files=get_bootstrap_files())
    ssh_client = AegeaSSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.connect(instance.public_dns_name, username="ubuntu", key_filename=ssh_key_filename)
    for i in range(900):
        try:
            if ssh_client.check_output("sudo jq .v1.errors /var/lib/cloud/data/result.json").strip() != "[]":
                raise Exception("cloud-init encountered errors")
            break
        except Exception as e:
            if "ENOENT" in str(e) or "EPERM" in str(e):
                time.sleep(1)
            else:
                raise
    else:
        raise Exception("cloud-init encountered errors")

    description = "Built by {} for {}".format(__name__, iam.CurrentUser().user.name)
    image = instance.create_image(Name=args.name, Description=description, BlockDeviceMappings=get_bdm())
    print(image.id)
    tags = dict([tag.split("=", 1) for tag in args.tags])
    add_tags(image, Owner=iam.CurrentUser().user.name, Base=args.ami, **tags)
    ec2.meta.client.get_waiter('image_available').wait(ImageIds=[image.id])
    while ec2.Image(image.id).state != "available":
        sys.stderr.write(".")
        sys.stderr.flush()
        time.sleep(1)
    instance.terminate()

parser = register_parser(build_image, help='Build an EC2 AMI')
parser.add_argument("name", default="test")
parser.add_argument("--snapshot-existing-host", type=str)
parser.add_argument("--wait-for-ami", action="store_true")
parser.add_argument("--ssh-key-name")
parser.add_argument("--instance-type", default="c3.xlarge")
parser.add_argument('--security-groups', nargs="+")
parser.add_argument('--base-ami', default=config.get("base_ami"))
parser.add_argument('--dry-run', '--dryrun', action='store_true')
parser.add_argument('--tags', nargs="+", default=[])
