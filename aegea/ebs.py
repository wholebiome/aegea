"""
Utilities to manage AWS Elastic Block Store volumes and snapshots.

To delete EBS volumes or snapshots, use ``aegea rm``.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, getpass
from datetime import datetime

from . import register_parser
from .ls import add_name, filter_collection, filter_and_tabulate, register_filtering_parser
from .util import Timestamp, paginate
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.aws import ARN, resources, clients, ensure_vpc, ensure_subnet, resolve_instance_id, add_tags
from .util.compat import lru_cache

def ebs(args):
    ebs_parser.print_help()

ebs_parser = register_parser(ebs, help="Manage Elastic Block Store resources", description=__doc__,
                             formatter_class=argparse.RawTextHelpFormatter)

def ls(args):
    @lru_cache()
    def instance_id_to_name(i):
        return add_name(resources.ec2.Instance(i)).name
    table = [{f: get_cell(i, f) for f in args.columns} for i in filter_collection(resources.ec2.volumes, args)]
    if "attachments" in args.columns:
        for row in table:
            row["attachments"] = ", ".join(instance_id_to_name(a["InstanceId"]) for a in row["attachments"])
    page_output(tabulate(table, args))

parser = register_filtering_parser(ls, parent=ebs_parser, help="List EC2 EBS volumes")

def snapshots(args):
    page_output(filter_and_tabulate(resources.ec2.snapshots.filter(OwnerIds=[ARN.get_account_id()]), args))

parser = register_filtering_parser(snapshots, parent=ebs_parser, help="List EC2 EBS snapshots")

def create(args):
    tags = dict(tag.split("=", 1) for tag in args.tags)
    create_args = dict(Size=args.size)
    for arg in "dry_run snapshot_id availability_zone volume_type iops encrypted kms_key_id".split():
        if getattr(args, arg) is not None:
            create_args["".join(x.capitalize() for x in arg.split("_"))] = getattr(args, arg)
    if "AvailabilityZone" not in create_args:
        create_args["AvailabilityZone"] = ensure_subnet(ensure_vpc()).availability_zone
    res = clients.ec2.create_volume(**create_args)
    clients.ec2.get_waiter('volume_available').wait(VolumeIds=[res["VolumeId"]])
    if tags:
        add_tags(resources.ec2.Volume(res["VolumeId"]), **tags)
    return res

parser_create = register_parser(create, parent=ebs_parser, help="Create an EBS volume")
parser_create.add_argument("--dry-run", action="store_true")
parser_create.add_argument("--snapshot-id")
parser_create.add_argument("--availability-zone")
parser_create.add_argument("--encrypted", action="store_true")
parser_create.add_argument("--kms-key-id")
parser_create.add_argument("--tags", nargs="+", default=[], metavar="TAG_NAME=VALUE")

def snapshot(args):
    return clients.ec2.create_snapshot(DryRun=args.dry_run, VolumeId=args.volume_id)
parser_snapshot = register_parser(snapshot, parent=ebs_parser, help="Create an EBS snapshot")

def attach(args):
    res = clients.ec2.attach_volume(DryRun=args.dry_run,
                                    VolumeId=args.volume_id,
                                    InstanceId=args.instance,
                                    Device=args.device)
    clients.ec2.get_waiter('volume_in_use').wait(VolumeIds=[res["VolumeId"]])
    return res
parser_attach = register_parser(attach, parent=ebs_parser, help="Attach an EBS volume to an EC2 instance")

def detach(args):
    res = clients.ec2.detach_volume(DryRun=args.dry_run,
                                    VolumeId=args.volume_id,
                                    InstanceId=args.instance,
                                    Device=args.device,
                                    Force=args.force)
    clients.ec2.get_waiter('volume_available').wait(VolumeIds=[res["VolumeId"]])
    return res
parser_detach = register_parser(detach, parent=ebs_parser, help="Detach an EBS volume from an EC2 instance")

def modify(args):
    modify_args = dict(VolumeId=args.volume_id, DryRun=args.dry_run)
    if args.size:
        modify_args.update(Size=args.size)
    if args.volume_type:
        modify_args.update(VolumeType=args.volume_type)
    if args.iops:
        modify_args.update(Iops=args.iops)
    res = clients.ec2.modify_volume(**modify_args)["VolumeModification"]
    #if args.wait:
    #    waiter = make_waiter(clients.ec2.describe_volumes_modifications, "VolumesModifications[].ModificationState",
    #                         "optimizing", "pathAny")
    #    waiter.wait(VolumeIds=[args.volume_id])
    return res
parser_modify = register_parser(modify, parent=ebs_parser, help="Change the size, type, or IOPS of an EBS volume")

for parser in parser_create, parser_modify:
    parser.add_argument("--size-gb", dest="size", type=int, help="Volume size in gigabytes")
    parser.add_argument("--volume-type", choices={"standard", "io1", "gp2", "sc1", "st1"},
                        help="io1, PIOPS SSD; gp2, general purpose SSD; sc1, cold HDD; st1, throughput optimized HDD")
    parser.add_argument("--iops", type=int)

def complete_volume_id(**kwargs):
    return [i["VolumeId"] for i in clients.ec2.describe_volumes()["Volumes"]]

for parser in parser_snapshot, parser_attach, parser_detach, parser_modify:
    parser.add_argument("volume_id").completer = complete_volume_id
    parser.add_argument("--dry-run", action="store_true")
    if parser in (parser_attach, parser_detach):
        parser.add_argument("instance", type=resolve_instance_id)
        parser.add_argument("device", choices=["xvd" + chr(i + 1) for i in range(ord("a"), ord("z"))])

parser_detach.add_argument("--force", action="store_true")
