"""
Launch a new EC2 instance.

Depending on the options given, this command may use the EC2
RunInstances, RequestSpotInstances, or RequestSpotFleet API. Run
"aegea ls", "aegea sirs" and "aegea sfrs" to see the status of the
instances and related spot instance and fleet requests.

The --spot and --spot-price options trigger the use of the
RequestSpotInstances API. The --duration-hours, --cores, and
--min-mem-per-core-gb options trigger the use of the RequestSpotFleet
API.

The return value (stdout) is a JSON object with one key, ``instance_id``.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, time, datetime, base64, json

from . import register_parser, logger, config

from .util import wait_for_port, validate_hostname, paginate
from .util.aws import (get_user_data, ensure_vpc, ensure_subnet, ensure_ingress_rule, ensure_security_group, DNSZone,
                       ensure_instance_profile, add_tags, resolve_security_group, get_bdm, resolve_instance_id,
                       expect_error_codes, resolve_ami, get_ondemand_price_usd, SpotFleetBuilder, resources, clients)
from .util.crypto import (new_ssh_key, add_ssh_host_key_to_known_hosts, ensure_ssh_key, hostkey_line,
                          get_ssh_key_filename)
from .util.exceptions import AegeaException
from botocore.exceptions import ClientError

def get_spot_bid_price(instance_type, ondemand_multiplier=1.2):
    ondemand_price = get_ondemand_price_usd(clients.ec2.meta.region_name, instance_type)
    return float(ondemand_price) * ondemand_multiplier

def get_startup_commands(args):
    return [
        "hostnamectl set-hostname {}.{}".format(args.hostname, config.dns.private_zone),
        "service awslogs restart",
        "echo tsc > /sys/devices/system/clocksource/clocksource0/current_clocksource"
    ] + args.commands

def launch(args, user_data_commands=None, user_data_packages=None, user_data_files=None):
    if args.spot_price or args.duration_hours or args.cores or args.min_mem_per_core_gb:
        args.spot = True
    if args.use_dns:
        dns_zone = DNSZone(config.dns.get("private_zone"))
        config.dns.private_zone = dns_zone.zone["Name"]
    ensure_ssh_key(args.ssh_key_name, verify_pem_file=args.verify_ssh_key_pem_file)
    try:
        i = resolve_instance_id(args.hostname)
        msg = "The hostname {} is being used by {} (state: {})"
        raise Exception(msg.format(args.hostname, i, resources.ec2.Instance(i).state["Name"]))
    except AegeaException:
        validate_hostname(args.hostname)
        assert not args.hostname.startswith("i-")
    args.ami = resolve_ami(args.ami)
    if args.subnet:
        subnet = resources.ec2.Subnet(args.subnet)
        vpc = resources.ec2.Vpc(subnet.vpc_id)
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
                                              packages=user_data_packages or args.packages,
                                              files=user_data_files))
    if args.iam_role:
        instance_profile = ensure_instance_profile(args.iam_role, policies=args.iam_policies)
        launch_spec["IamInstanceProfile"] = dict(Arn=instance_profile.arn)
    if not args.spot:
        launch_spec["SubnetId"] = subnet.id
    if args.availability_zone:
        launch_spec["Placement"] = dict(AvailabilityZone=args.availability_zone)
    if args.client_token is None:
        from getpass import getuser
        from socket import gethostname
        args.client_token = "{}.{}.{}:{}@{}".format(resources.iam.CurrentUser().user.name,
                                                    __name__,
                                                    int(time.time()),
                                                    getuser(),
                                                    gethostname().split(".")[0])
        args.client_token = args.client_token[:64]
    try:
        if args.spot:
            launch_spec["UserData"] = base64.b64encode(launch_spec["UserData"]).decode()
            if args.duration_hours or args.cores or args.min_mem_per_core_gb:
                spot_fleet_args = dict(launch_spec=launch_spec, client_token=args.client_token)
                for arg in "cores", "min_mem_per_core_gb", "spot_price", "duration_hours", "dry_run":
                    if getattr(args, arg, None):
                        spot_fleet_args[arg] = getattr(args, arg)
                if "cores" in spot_fleet_args:
                    spot_fleet_args["min_cores_per_instance"] = spot_fleet_args["cores"]
                spot_fleet_builder = SpotFleetBuilder(**spot_fleet_args)
                logger.info("Launching {}".format(spot_fleet_builder))
                sfr_id = spot_fleet_builder()
                instances = []
                while not instances:
                    res = clients.ec2.describe_spot_fleet_instances(SpotFleetRequestId=sfr_id)
                    instances = res["ActiveInstances"]
                # FIXME: there may be multiple instances, and spot fleet provides no indication of whether the SFR is
                # fulfilled
                instance = resources.ec2.Instance(instances[0]["InstanceId"])
            else:
                if args.spot_price is None:
                    args.spot_price = get_spot_bid_price(args.instance_type)
                logger.info("Bidding {} for a {} spot instance".format(args.spot_price, args.instance_type))
                res = clients.ec2.request_spot_instances(
                    SpotPrice=str(args.spot_price),
                    ValidUntil=datetime.datetime.utcnow()+datetime.timedelta(hours=1),
                    LaunchSpecification=launch_spec,
                    ClientToken=args.client_token,
                    DryRun=args.dry_run
                )
                sir_id = res["SpotInstanceRequests"][0]["SpotInstanceRequestId"]
                clients.ec2.get_waiter('spot_instance_request_fulfilled').wait(SpotInstanceRequestIds=[sir_id])
                res = clients.ec2.describe_spot_instance_requests(SpotInstanceRequestIds=[sir_id])
                instance = resources.ec2.Instance(res["SpotInstanceRequests"][0]["InstanceId"])
        else:
            instances = resources.ec2.create_instances(MinCount=1, MaxCount=1, ClientToken=args.client_token,
                                                       DryRun=args.dry_run, **launch_spec)
            instance = instances[0]
    except ClientError as e:
        expect_error_codes(e, "DryRunOperation")
        logger.info("Dry run succeeded")
        exit()
    instance.wait_until_running()
    hkl = hostkey_line(hostnames=[], key=ssh_host_key).strip()
    tags = dict([tag.split("=", 1) for tag in args.tags])
    add_tags(instance, Name=args.hostname, Owner=resources.iam.CurrentUser().user.name,
             SSHHostPublicKeyPart1=hkl[:255], SSHHostPublicKeyPart2=hkl[255:], **tags)
    if args.use_dns:
        dns_zone.update(args.hostname, instance.private_dns_name)
    while not instance.public_dns_name:
        instance = resources.ec2.Instance(instance.id)
        time.sleep(1)
    add_ssh_host_key_to_known_hosts(hostkey_line([instance.public_dns_name], ssh_host_key))
    if args.wait_for_ssh:
        wait_for_port(instance.public_dns_name, 22)
    if args.essential_services:
        filter_args = dict(logGroupName="syslog", logStreamNames=[instance.private_dns_name], filterPattern="service",
                           startTime=int((time.time()-900)*1000))
        for event in paginate(clients.logs.get_paginator('filter_log_events'), **filter_args):
            # print(event["timestamp"], event["message"])
            raise NotImplementedError()
    # FIXME: this doesn't work. Figure out a way to vivify current user's account
    #from .util.ssh import AegeaSSHClient
    #try:
    #    ssh_client = AegeaSSHClient()
    #    ssh_client.load_system_host_keys()
    #    ssh_client.connect(instance.public_dns_name, password="password", look_for_keys=False)
    #    ssh_client.check_output("systemctl")
    #except Exception as e:
    #    print(e)
    logger.info("Launched %s in %s", instance, subnet)
    return dict(instance_id=instance.id)

parser = register_parser(launch, help='Launch a new EC2 instance', description=__doc__)
parser.add_argument('hostname')
parser.add_argument('--commands', nargs="+")
parser.add_argument('--packages', nargs="+")
parser.add_argument("--ssh-key-name", default=__name__)
parser.add_argument('--no-verify-ssh-key-pem-file', dest='verify_ssh_key_pem_file', action='store_false')
parser.add_argument('--ami')
parser.add_argument('--spot', action='store_true')
parser.add_argument('--duration-hours', type=float, help='Terminate the spot instance after this number of hours')
parser.add_argument('--cores', type=int)
parser.add_argument('--min-mem-per-core-gb', type=float)
parser.add_argument('--instance-type', '-t', default="t2.micro")
parser.add_argument('--spot-price', type=float,
                    help="Maximum bid price for spot instances. Defaults to 1.2x the ondemand price.")
parser.add_argument('--no-dns', dest='use_dns', action='store_false',
                    help="Skip registering instance name in private DNS. Use if you don't use private DNS, or don't want the launching principal to have Route53 write access.")  # noqa
parser.add_argument('--client-token', help="Token used to identify your instance, SIR or SFR")
parser.add_argument('--subnet')
parser.add_argument('--availability-zone', '-z')
parser.add_argument('--security-groups', nargs="+")
parser.add_argument('--tags', nargs="+", default=[])
parser.add_argument('--wait-for-ssh', action='store_true')
parser.add_argument('--essential-services', nargs="+")
parser.add_argument('--iam-role', default=__name__)
parser.add_argument('--iam-policies', nargs="+", default=["IAMReadOnlyAccess", "AmazonElasticFileSystemFullAccess"],
                    help='Ensure the default or specified IAM role has the listed IAM managed policies attached')
parser.add_argument('--dry-run', '--dryrun', action='store_true')
