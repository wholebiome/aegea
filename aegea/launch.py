from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, time, datetime, base64
import boto3

from . import register_parser, logger, config

from .util import wait_for_port, validate_hostname
from .util.aws import (get_user_data, ensure_vpc, ensure_subnet, ensure_ingress_rule, ensure_security_group, DNSZone,
                       ensure_instance_profile, add_tags, resolve_security_group, get_bdm, resolve_instance_id,
                       expect_error_codes, resolve_ami)
from .util.crypto import new_ssh_key, add_ssh_host_key_to_known_hosts, ensure_ssh_key, hostkey_line
from .util.exceptions import AegeaException
from botocore.exceptions import ClientError

def get_startup_commands(args):
    return [
        "hostnamectl set-hostname {}.{}".format(args.hostname, config.dns.private_zone),
        "service awslogs restart",
        "sed -i '/%sudo/ s/ALL$/NOPASSWD:ALL/' /etc/sudoers",
        "echo tsc > /sys/devices/system/clocksource/clocksource0/current_clocksource",
        "bash -c 'devices=(/dev/xvd[b-m]); yes|mdadm --create --force --verbose /dev/md0 --level=0 --raid-devices=${#devices[@]} ${devices[@]}'",
        "blockdev --setra 16384 /dev/md0",
        "mkfs.btrfs --force /dev/md0",
        "mount /dev/md0 /mnt"
    ]

def launch(args, user_data_commands=None, user_data_packages=None, user_data_files=None):
    ec2 = boto3.resource("ec2")
    iam = boto3.resource("iam")
    if not args.no_dns:
        dns_zone = DNSZone(config.dns.private_zone)
    ensure_ssh_key(args.ssh_key_name)
    try:
        i = resolve_instance_id(args.hostname)
        raise Exception("The hostname {} is being used by {} (state: {})".format(args.hostname, i, ec2.Instance(i).state["Name"]))
    except AegeaException:
        validate_hostname(args.hostname)
        assert not args.hostname.startswith("i-")
    args.ami = resolve_ami(args.ami)
    if args.subnet:
        subnet = ec2.Subnet(args.subnet)
        vpc = ec2.Vpc(subnet.vpc_id)
    else:
        vpc = ensure_vpc()
        subnet = ensure_subnet(vpc)

    if args.security_groups:
        security_groups = [resolve_security_group(sg, vpc) for sg in args.security_groups]
    else:
        security_groups = [ensure_security_group(__name__, vpc)]

    ssh_host_key = new_ssh_key()
    launch_spec = dict(ImageId=args.ami,
                       KeyName=args.ssh_key_name,
                       SecurityGroupIds=[sg.id for sg in security_groups],
                       InstanceType=args.instance_type,
                       BlockDeviceMappings=get_bdm(),
                       UserData=get_user_data(host_key=ssh_host_key,
                                              commands=user_data_commands or get_startup_commands(args),
                                              packages=user_data_packages,
                                              files=user_data_files))
    if args.iam_role:
        instance_profile = ensure_instance_profile(args.iam_role, policies=args.iam_policies)
        launch_spec["IamInstanceProfile"] = dict(Arn=instance_profile.arn)
    if not args.spot:
        launch_spec["SubnetId"] = subnet.id
    if args.availability_zone:
        launch_spec["Placement"] = dict(AvailabilityZone=args.availability_zone)
    try:
        if args.spot:
            launch_spec["UserData"] = base64.b64encode(launch_spec["UserData"].encode()).decode()
            logger.info("Bidding {} for a {} spot instance".format(args.spot_bid, args.instance_type))
            res = ec2.meta.client.request_spot_instances(SpotPrice=str(args.spot_bid),
                                                         ValidUntil=datetime.datetime.utcnow()+datetime.timedelta(hours=1),
                                                         LaunchSpecification=launch_spec,
                                                         DryRun=args.dry_run)
            sir_id = res["SpotInstanceRequests"][0]["SpotInstanceRequestId"]
            ec2.meta.client.get_waiter('spot_instance_request_fulfilled').wait(SpotInstanceRequestIds=[sir_id])
            instance = ec2.Instance(ec2.meta.client.describe_spot_instance_requests(SpotInstanceRequestIds=[sir_id])["SpotInstanceRequests"][0]["InstanceId"])
        else:
            instances = ec2.create_instances(MinCount=1, MaxCount=1, DryRun=args.dry_run, **launch_spec)
            instance = instances[0]
    except ClientError as e:
        expect_error_codes(e, "DryRunOperation")
        logger.info("Dry run succeeded")
        exit()
    instance.wait_until_running()
    hkl = hostkey_line(hostnames=[], key=ssh_host_key).strip()
    tags = dict([tag.split("=", 1) for tag in args.tags])
    add_tags(instance, Name=args.hostname, Owner=iam.CurrentUser().user.name, SSHHostPublicKeyPart1=hkl[:255], SSHHostPublicKeyPart2=hkl[255:], **tags)
    if not args.no_dns:
        dns_zone.update(args.hostname, instance.private_dns_name)
    while not instance.public_dns_name:
        instance = ec2.Instance(instance.id)
        time.sleep(1)
    add_ssh_host_key_to_known_hosts(hostkey_line([instance.public_dns_name], ssh_host_key))
    if args.wait_for_ssh:
        wait_for_port(instance.public_dns_name, 22)
    logger.info("Launched %s in %s", instance, subnet)
    return instance

parser = register_parser(launch, help='Launch a new EC2 instance')
parser.add_argument('hostname')
parser.add_argument('--instance-type', '-t', default="t2.micro")
parser.add_argument("--ssh-key-name", default=__name__)
parser.add_argument('--ami')
parser.add_argument('--spot', action='store_true')
parser.add_argument('--no-dns', action='store_true')
parser.add_argument('--spot-bid', type=float, default=1.0)
parser.add_argument('--subnet')
parser.add_argument('--availability-zone', '-z')
parser.add_argument('--security-groups', nargs="+")
parser.add_argument('--tags', nargs="+", default=[])
parser.add_argument('--wait-for-ssh', action='store_true')
parser.add_argument('--iam-role', default=__name__)
parser.add_argument('--iam-policies', nargs="+", default=["IAMReadOnlyAccess", "AmazonElasticFileSystemFullAccess"],
                    help='Ensure the default or specified IAM role has the listed IAM managed policies attached')
parser.add_argument('--dry-run', action='store_true')
