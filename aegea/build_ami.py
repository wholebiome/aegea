from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json, time
from argparse import Namespace
from collections import OrderedDict

from . import register_parser, logger, config, __version__
from .util.aws import (locate_ubuntu_ami, get_user_data, ensure_vpc, ensure_subnet, ensure_ingress_rule,
                       ensure_security_group, add_tags, get_bdm, resolve_instance_id, resources, clients)
from .util.crypto import ensure_ssh_key, new_ssh_key, add_ssh_host_key_to_known_hosts, get_ssh_key_filename
from .launch import launch

def get_bootstrap_files(rootfs_skel_dirs):
    manifest = OrderedDict()
    aegea_conf = os.getenv("AEGEA_CONFIG_FILE")

    for rootfs_skel_dir in rootfs_skel_dirs:
        if rootfs_skel_dir == "auto":
            fn = os.path.join(os.path.dirname(__file__), "rootfs.skel")
        elif aegea_conf:
            # FIXME: not compatible with colon-separated AEGEA_CONFIG_FILE
            fn = os.path.join(os.path.dirname(aegea_conf), rootfs_skel_dir)
        elif os.path.exists(rootfs_skel_dir):
            fn = os.path.abspath(os.path.normpath(rootfs_skel_dir))
        else:
            raise Exception("rootfs_skel directory {} not found".format(fn))
        logger.debug("Trying rootfs.skel: %s" % fn)
        if not os.path.exists(fn):
            raise Exception("rootfs_skel directory {} not found".format(fn))
        for root, dirs, files in os.walk(fn):
            for file_ in files:
                path = os.path.join("/", os.path.relpath(root, fn), file_)
                with open(os.path.join(root, file_)) as fh:
                    manifest[path] = dict(path=path,
                                          content=fh.read(),
                                          permissions=oct(os.stat(os.path.join(root, file_)).st_mode)[-3:])
    return manifest.values()

def build_ami(args):
    from .util.ssh import AegeaSSHClient
    ssh_key_filename = get_ssh_key_filename(args, base_name=__name__)
    if args.snapshot_existing_host:
        instance = resources.ec2.Instance(resolve_instance_id(args.snapshot_existing_host))
        args.ami = instance.image_id
    else:
        if args.base_ami == "auto":
            args.ami = locate_ubuntu_ami(product=args.base_ami_product, region=clients.ec2.meta.region_name)
        else:
            args.ami = args.base_ami
        hostname = "{}-{}-{}".format(__name__, args.name, int(time.time()))
        args.hostname = hostname.replace(".", "-").replace("_", "-")
        args.wait_for_ssh = True
        fields = "spot spot_price duration_hours iam_role subnet availability_zone use_dns cores min_mem_per_core_gb client_token essential_services ami_tags"  # noqa
        for field in fields.split():
            setattr(args, field, None)
        instance = resources.ec2.Instance(launch(args, files=get_bootstrap_files(args.rootfs_skel_dirs))["instance_id"])
    ssh_client = AegeaSSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.connect(instance.public_dns_name, username="ubuntu", key_filename=ssh_key_filename)
    for i in range(900):
        try:
            ssh_client.check_call("ls /var/lib/cloud/data/result.json")
            if ssh_client.check_output("sudo jq .v1.errors /var/lib/cloud/data/result.json").strip() != "[]":
                raise Exception("cloud-init encountered errors")
            break
        except Exception as e:
            if "ENOENT" in str(e) or "EPERM" in str(e) or "No such file or directory" in str(e):
                time.sleep(1)
            else:
                raise
    else:
        raise Exception("cloud-init encountered errors")

    description = "Built by {} for {}".format(__name__, resources.iam.CurrentUser().user.name)
    image = instance.create_image(Name=args.name, Description=description, BlockDeviceMappings=get_bdm())
    tags = dict(tag.split("=", 1) for tag in args.tags)
    # FIXME: add base AMI name
    tags.update(Owner=resources.iam.CurrentUser().user.name, Base=args.ami, AegeaVersion=__version__)
    add_tags(image, **tags)
    logger.info("Waiting for %s to become available...", image.id)
    clients.ec2.get_waiter("image_available").wait(ImageIds=[image.id])
    while resources.ec2.Image(image.id).state != "available":
        sys.stderr.write(".")
        sys.stderr.flush()
        time.sleep(1)
    instance.terminate()
    return dict(ImageID=image.id, **tags)

parser = register_parser(build_ami, help="Build an EC2 AMI")
parser.add_argument("name", default="test")
parser.add_argument("--snapshot-existing-host", type=str, metavar="HOST")
parser.add_argument("--wait-for-ami", action="store_true")
parser.add_argument("--ssh-key-name")
parser.add_argument("--no-verify-ssh-key-pem-file", dest="verify_ssh_key_pem_file", action="store_false")
parser.add_argument("--instance-type", default="c3.xlarge", help="Instance type to use for building the AMI")
parser.add_argument("--security-groups", nargs="+")
parser.add_argument("--base-ami")
parser.add_argument("--base-ami-product",
                    help="Ubuntu cloud image manifest product to use, e.g. com.ubuntu.cloud:server:16.04:amd64")
parser.add_argument("--dry-run", "--dryrun", action="store_true")
parser.add_argument("--tags", nargs="+", default=[], metavar="NAME=VALUE", help="Tag the resulting AMI with these tags")
parser.add_argument("--cloud-config-data", type=json.loads)
