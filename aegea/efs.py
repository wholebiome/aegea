"""
Utilities to manage AWS Elastic Filesystem resources.

To delete EFS filesystems, use ``aegea rm``.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, getpass, base64
from datetime import datetime

from . import register_parser
from .ls import add_name, filter_collection, filter_and_tabulate, register_listing_parser
from .util import Timestamp, paginate
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.aws import clients, ensure_vpc, ensure_subnet, encode_tags, make_waiter, ensure_security_group
from .util.compat import lru_cache

def efs(args):
    efs_parser.print_help()

efs_parser = register_parser(efs, help="Manage Elastic Filesystem resources", description=__doc__,
                             formatter_class=argparse.RawTextHelpFormatter)

def ls(args):
    table = []
    for filesystem in clients.efs.describe_file_systems()["FileSystems"]:
        filesystem["tags"] = clients.efs.describe_tags(FileSystemId=filesystem["FileSystemId"])["Tags"]
        for mount_target in clients.efs.describe_mount_targets(FileSystemId=filesystem["FileSystemId"])["MountTargets"]:
            mount_target.update(filesystem)
            table.append(mount_target)
    args.columns += args.mount_target_columns
    page_output(tabulate(table, args, cell_transforms={"SizeInBytes": lambda x, r: x.get("Value") if x else None}))

parser = register_listing_parser(ls, parent=efs_parser, help="List EFS filesystems")
parser.add_argument("--mount-target-columns", nargs="+")

def create(args):
    vpc = ensure_vpc()
    creation_token = base64.b64encode(bytearray(os.urandom(24))).decode()
    fs = clients.efs.create_file_system(CreationToken=creation_token, PerformanceMode=args.performance_mode)
    clients.efs.create_tags(FileSystemId=fs["FileSystemId"], Tags=encode_tags(args.tags + ["Name=" + args.name]))
    waiter = make_waiter(clients.efs.describe_file_systems, "FileSystems[].LifeCycleState", "available", "pathAny")
    waiter.wait(FileSystemId=fs["FileSystemId"])
    for subnet in vpc.subnets.all():
        clients.efs.create_mount_target(FileSystemId=fs["FileSystemId"],
                                        SubnetId=subnet.id,
                                        SecurityGroups=[ensure_security_group(g, vpc).id for g in args.security_groups])
    return fs

parser = register_parser(create, parent=efs_parser, help="Create an EFS filesystem")
parser.add_argument("name")
parser.add_argument("--performance-mode", choices={"generalPurpose", "maxIO"}, default="generalPurpose")
parser.add_argument("--tags", nargs="+", default=[], metavar="NAME=VALUE")
parser.add_argument("--security-groups", nargs="+", default=[__name__])
