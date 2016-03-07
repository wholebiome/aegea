from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, time, datetime, base64
import boto3

from . import register_parser, logger, config

from .util import wait_for_port
from .util.aws import get_user_data, ensure_vpc, ensure_subnet, ensure_ingress_rule, ensure_security_group, DNSZone, ensure_instance_profile, set_tags, resolve_security_group
from .util.crypto import new_ssh_key, add_ssh_host_key_to_known_hosts, ensure_ssh_key

def get_startup_commands(args):
    return [
        "hostnamectl set-hostname {}.{}".format(args.hostname, config.private_dns_zone)
    ]

def launch(args):
    ec2 = boto3.resource("ec2")
    ensure_ssh_key(args.ssh_key_name)
    assert not args.hostname.startswith("i-")
    if args.ami is None:
        filters = dict(Owners=["self"], Filters=[dict(Name="state", Values=["available"])])
        amis = sorted(ec2.images.filter(**filters), key=lambda ami: ami.creation_date)
        args.ami = amis[-1].id

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
                       UserData=get_user_data(host_key=ssh_host_key, commands=get_startup_commands(args)))
    if args.iam_role:
        instance_profile = ensure_instance_profile(args.iam_role)
        launch_spec["IamInstanceProfile"] = dict(Arn=instance_profile.arn)
    if not args.spot:
        launch_spec["SubnetId"] = subnet.id
    if args.availability_zone:
        launch_spec["Placement"] = dict(AvailabilityZone=args.availability_zone)
    if args.spot:
        launch_spec["UserData"] = base64.b64encode(launch_spec["UserData"].encode()).decode()
        res = ec2.meta.client.request_spot_instances(SpotPrice=str(args.spot_bid),
                                                     ValidUntil=datetime.datetime.utcnow()+datetime.timedelta(hours=1),
                                                     LaunchSpecification=launch_spec)
        sir_id = res["SpotInstanceRequests"][0]["SpotInstanceRequestId"]
        ec2.meta.client.get_waiter('spot_instance_request_fulfilled').wait(SpotInstanceRequestIds=[sir_id])
        instance = ec2.Instance(ec2.meta.client.describe_spot_instance_requests(SpotInstanceRequestIds=[sir_id])["SpotInstanceRequests"][0]["InstanceId"])
    else:
        instances = ec2.create_instances(MinCount=1, MaxCount=1, **launch_spec)
        instance = instances[0]
    instance.wait_until_running()
    set_tags(instance, Name=args.hostname)
    DNSZone(config.private_dns_zone).update(args.hostname, instance.private_dns_name)
    while not instance.public_dns_name:
        instance = ec2.Instance(instance.id)
        time.sleep(1)
    add_ssh_host_key_to_known_hosts(instance.public_dns_name, ssh_host_key)
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
parser.add_argument('--spot-bid', type=float, default=1.0)
parser.add_argument('--subnet')
parser.add_argument('--availability-zone', '-z')
parser.add_argument('--security-groups', nargs="+")
parser.add_argument('--wait-for-ssh', action='store_true')
