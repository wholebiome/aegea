import os, sys, argparse, subprocess
import boto3
from . import register_parser, logger

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
        elif name.startswith("AKIA") and len(name) == 20 and name.upper() == name:
            boto3.client("iam").delete_access_key(AccessKeyId=name)
        elif name.startswith("AROA") and len(name) == 21 and name.upper() == name:
            for role in boto3.resource("iam").roles.all():
                if role.role_id == name:
                    logger.info("Deleting %s", role)
                    for instance_profile in role.instance_profiles.all():
                        instance_profile.remove_role(RoleName=role.name)
                        instance_profile.delete()
                    for policy in role.attached_policies.all():
                        role.detach_policy(PolicyArn=policy.arn)
                    role.delete()
            else:
                raise Exception("Role {} not found".format(name))
        else:
            raise Exception("Name {} not recognized as an AWS resource".format(name))

parser = register_parser(rm, help='Remove resources', description="List resources to be removed by their ID or ARN, such as ami-eb957a8b, AIDAJYZD67Q2SUMUA2JBC, or arn:aws:iam::123456789012:user/foo.")
parser.add_argument('names', nargs='+')
