"""
Remove or deprovision AWS EC2, IAM, and other resources. By default, this command performs a dry run; the -f/--force
option is required to actually execute the operation.

List resources to be removed by their ID or ARN, such as ami-eb957a8b, AIDAJYZD67Q2SUMUA2JBC, or
arn:aws:iam::123456789012:user/foo.

EC2 key pairs have no ARNs and no distingiushing ID prefix. To delete them by name, use the --key-pair option.
"""

import os, sys, argparse, subprocess
import boto3
from . import register_parser, logger
from .util.aws import expect_error_codes
from botocore.exceptions import ClientError

def rm(args):
    for name in args.names:
        try:
            if args.key_pair:
                boto3.resource("ec2").KeyPair(name).delete(DryRun=not args.force)
            elif name.startswith("sg-"):
                boto3.resource("ec2").SecurityGroup(name).delete(DryRun=not args.force)
            elif name.startswith("vol-"):
                boto3.resource("ec2").Volume(name).delete(DryRun=not args.force)
            elif name.startswith("snap-"):
                boto3.resource("ec2").Snapshot(name).delete(DryRun=not args.force)
            elif name.startswith("ami-"):
                image = boto3.resource("ec2").Image(name)
                snapshot_id = image.block_device_mappings[0].get("Ebs", {}).get("SnapshotId")
                image.deregister(DryRun=not args.force)
                if snapshot_id:
                    boto3.resource("ec2").Snapshot(snapshot_id).delete(DryRun=not args.force)
            elif name.startswith("sir-"):
                boto3.client("ec2").cancel_spot_instance_requests(SpotInstanceRequestIds=[name], DryRun=not args.force)
            elif name.startswith("sfr-"):
                boto3.client("ec2").cancel_spot_fleet_requests(SpotFleetRequestIds=[name],
                                                               TerminateInstances=False,
                                                               DryRun=not args.force)
            elif name.startswith("AKIA") and len(name) == 20 and name.upper() == name:
                boto3.client("iam").delete_access_key(AccessKeyId=name) if args.force else True
            elif name.startswith("AROA") and len(name) == 21 and name.upper() == name:
                for role in boto3.resource("iam").roles.all():
                    if role.role_id == name:
                        logger.info("Deleting %s", role)
                        for instance_profile in role.instance_profiles.all():
                            instance_profile.remove_role(RoleName=role.name) if args.force else True
                            instance_profile.delete() if args.force else True
                        for policy in role.attached_policies.all():
                            role.detach_policy(PolicyArn=policy.arn) if args.force else True
                        role.delete() if args.force else True
                else:
                    raise Exception("Role {} not found".format(name))
            else:
                raise Exception("Name {} not recognized as an AWS resource".format(name))
        except ClientError as e:
            expect_error_codes(e, "DryRunOperation")
    if not args.force:
        logger.info("Dry run succeeded. Run %s again with --force (-f) to actually remove.", __name__)

parser = register_parser(rm, help='Remove or deprovision resources', description=__doc__)
parser.add_argument('names', nargs='+')
parser.add_argument('-f', '--force', action="store_true")
parser.add_argument('--key-pair', action="store_true",
                    help='Assume input names are EC2 SSH key pair names (required when deleting key pairs, since they have no ID or ARN)')
