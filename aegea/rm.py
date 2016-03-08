import os, sys, argparse, subprocess
import boto3
from . import register_parser

def rm(args):
    for name in args.names:
        if name.startswith("sg-"):
            boto3.resource("ec2").SecurityGroup(name).delete()
        elif name.startswith("vol-"):
            boto3.resource("ec2").Volume(name).delete()
        elif name.startswith("snap-"):
            boto3.resource("ec2").Snapshot(name).delete()
        elif name.startswith("ami-"):
            image = boto3.resource("ec2").Image(name)
            snapshot_id = image.block_device_mappings[0].get("Ebs", {}).get("SnapshotId")
            image.deregister()
            if snapshot_id:
                boto3.resource("ec2").Snapshot(snapshot_id).delete()
        elif name.startswith("sir-"):
            boto3.client("ec2").cancel_spot_instance_requests(SpotInstanceRequestIds=[name])
        else:
            raise Exception("Name {} not recognized as an AWS resource".format(name))

parser = register_parser(rm, help='Remove resources', description="List resources to be removed by their ID or ARN, such as ami-eb957a8b, AIDAJYZD67Q2SUMUA2JBC, or arn:aws:iam::123456789012:user/foo.")
parser.add_argument('names', nargs='+')
