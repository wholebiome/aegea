from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json, io, gzip, time
import requests
from warnings import warn
from datetime import datetime, timedelta

import botocore.session
from botocore.exceptions import ClientError
from botocore.utils import parse_to_aware_datetime

from ... import logger
from .. import VerboseRepr, paginate
from ..exceptions import AegeaException
from ..compat import str
from . import clients, resources

def get_assume_role_policy_doc(*principals):
    # See http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Principal
    p = IAMPolicyBuilder()
    for principal in principals:
        if isinstance(principal, dict):
            p.add_statement(principal=principal, action="sts:AssumeRole")
        elif hasattr(principal, "arn"):
            p.add_statement(principal={"AWS": principal.arn}, action="sts:AssumeRole")
        else:
            p.add_statement(principal={"Service": principal + ".amazonaws.com"}, action="sts:AssumeRole")
    return json.dumps(p.policy)

def locate_ami(product, region=None, channel="releases", stream="released", root_store="ssd", virt="hvm"):
    """
    Examples::
        locate_ami(product="com.ubuntu.cloud:server:16.04:amd64", channel="daily", stream="daily", region="us-west-2")
        locate_ami(product="Amazon Linux AMI 2016.09")
    """
    if region is None:
        region = clients.ec2.meta.region_name
    if product.startswith("com.ubuntu.cloud"):
        partition = "aws"
        if region.startswith("cn-"):
            partition = "aws-cn"
        elif region.startswith("us-gov-"):
            partition = "aws-govcloud"
        if partition not in {"aws", "aws-cn", "aws-govcloud"}:
            raise AegeaException("Unrecognized partition {}".format(partition))
        manifest_url = "https://cloud-images.ubuntu.com/{channel}/streams/v1/com.ubuntu.cloud:{stream}:{partition}.json"
        manifest_url = manifest_url.format(partition=partition, channel=channel, stream=stream)
        manifest = requests.get(manifest_url).json()
        if product not in manifest["products"]:
            raise AegeaException("Ubuntu version {} not found in Ubuntu cloud image manifest".format(product))
        versions = manifest["products"][product]["versions"]
        for version in sorted(versions.keys(), reverse=True)[:8]:
            for ami in versions[version]["items"].values():
                if ami["crsn"] == region and ami["root_store"] == root_store and ami["virt"] == virt:
                    logger.info("Found %s for %s", ami["id"], ":".join([product, version, region, root_store, virt]))
                    return ami["id"]
    elif product.startswith("Amazon Linux"):
        filters = {"root-device-type": "ebs" if root_store == "ssd" else root_store, "virtualization-type": virt,
                   "architecture": "x86_64", "owner-alias": "amazon", "state": "available"}
        images = resources.ec2.images.filter(Filters=[dict(Name=k, Values=[v]) for k, v in filters.items()])
        for image in sorted(images, key=lambda i: i.creation_date, reverse=True):
            if root_store == "ebs" and not image.name.endswith("x86_64-gp2"):
                continue
            if image.name.startswith("amzn-ami-" + virt) and image.description.startswith(product):
                return image.image_id
    raise AegeaException("No AMI found for {} {} {} {}".format(product, region, root_store, virt))

def ensure_vpc():
    for vpc in resources.ec2.vpcs.filter(Filters=[dict(Name="isDefault", Values=["true"])]):
        break
    else:
        for vpc in resources.ec2.vpcs.all():
            break
        else:
            from ... import config
            logger.info("Creating VPC with CIDR %s", config.vpc.cidr[ARN.get_region()])
            vpc = resources.ec2.create_vpc(CidrBlock=config.vpc.cidr[ARN.get_region()])
            clients.ec2.get_waiter("vpc_available").wait(VpcIds=[vpc.id])
            add_tags(vpc, Name=__name__)
            vpc.modify_attribute(EnableDnsSupport=dict(Value=config.vpc.enable_dns_support))
            vpc.modify_attribute(EnableDnsHostnames=dict(Value=config.vpc.enable_dns_hostnames))
            internet_gateway = resources.ec2.create_internet_gateway()
            vpc.attach_internet_gateway(InternetGatewayId=internet_gateway.id)
            for route_table in vpc.route_tables.all():
                route_table.create_route(DestinationCidrBlock="0.0.0.0/0", GatewayId=internet_gateway.id)
            ensure_subnet(vpc)
    return vpc

def availability_zones():
    for az in clients.ec2.describe_availability_zones()["AvailabilityZones"]:
        yield az["ZoneName"]

def ensure_subnet(vpc):
    for subnet in vpc.subnets.all():
        break
    else:
        from ipaddress import ip_network
        from ... import config
        subnet_cidrs = ip_network(str(config.vpc.cidr[ARN.get_region()])).subnets(new_prefix=config.vpc.subnet_prefix)
        for az, subnet_cidr in zip(availability_zones(), subnet_cidrs):
            logger.info("Creating subnet with CIDR %s in %s, %s", subnet_cidr, vpc, az)
            subnet = resources.ec2.create_subnet(VpcId=vpc.id, CidrBlock=str(subnet_cidr), AvailabilityZone=az)
            clients.ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet.id])
            add_tags(subnet, Name=__name__)
            clients.ec2.modify_subnet_attribute(SubnetId=subnet.id,
                                                MapPublicIpOnLaunch=dict(Value=config.vpc.map_public_ip_on_launch))
    return subnet

def ensure_ingress_rule(security_group, **kwargs):
    cidr_ip = kwargs.pop("CidrIp")
    for rule in security_group.ip_permissions:
        ip_range_matches = any(cidr_ip == ip_range["CidrIp"] for ip_range in rule["IpRanges"])
        opts_match = all(rule.get(arg) == kwargs[arg] for arg in kwargs)
        if ip_range_matches and opts_match:
            break
    else:
        security_group.authorize_ingress(CidrIp=cidr_ip, **kwargs)

def resolve_security_group(name, vpc=None):
    if vpc is None:
        vpc = ensure_vpc()
    sgs = vpc.security_groups.filter(GroupNames=[name]) if vpc.is_default else vpc.security_groups.all()
    for security_group in sgs:
        if security_group.group_name == name:
            return security_group
    raise KeyError(name)

def ensure_security_group(name, vpc, tcp_ingress=[dict(port=22, cidr="0.0.0.0/0")]):
    try:
        security_group = resolve_security_group(name, vpc)
    except (ClientError, KeyError):
        logger.info("Creating security group %s for %s", name, vpc)
        security_group = vpc.create_security_group(GroupName=name, Description=name)
        for i in range(90):
            try:
                clients.ec2.describe_security_groups(GroupIds=[security_group.id])
            except ClientError:
                time.sleep(1)
    for rule in tcp_ingress:
        ensure_ingress_rule(security_group, IpProtocol="tcp", FromPort=rule["port"], ToPort=rule["port"],
                            CidrIp=rule["cidr"])
    return security_group

def ensure_s3_bucket(name=None, policy=None):
    if name is None:
        name = "aegea-assets-{}".format(ARN.get_account_id())
    bucket = resources.s3.Bucket(name)
    bucket.create()
    bucket.wait_until_exists()
    if policy:
        bucket.Policy().put(Policy=str(policy))
    return bucket

def get_client_token(iam_username, service):
    from getpass import getuser
    from socket import gethostname
    tok = "{}.{}.{}:{}@{}".format(iam_username, service, int(time.time()), getuser(), gethostname().split(".")[0])
    return tok[:64]

class DNSZone(VerboseRepr):
    def __init__(self, zone_name=None, use_unique_private_zone=True, create_default_private_zone=True):
        if zone_name:
            self.zone = clients.route53.list_hosted_zones_by_name(DNSName=zone_name)["HostedZones"][0]
            assert self.zone["Name"].rstrip(".") == zone_name.rstrip(".")
        elif use_unique_private_zone:
            private_zones = []
            for zone in paginate(clients.route53.get_paginator("list_hosted_zones")):
                if zone.get("Config", {}).get("PrivateZone") is True:
                    private_zones.append(zone)
            if len(private_zones) == 1:
                self.zone = private_zones[0]
            elif len(private_zones) == 0 and create_default_private_zone:
                vpc = ensure_vpc()
                vpc.modify_attribute(EnableDnsSupport=dict(Value=True))
                vpc.modify_attribute(EnableDnsHostnames=dict(Value=True))
                res = clients.route53.create_hosted_zone(Name="aegea.",
                                                         CallerReference=get_client_token(None, "route53"),
                                                         HostedZoneConfig=dict(PrivateZone=True),
                                                         VPC=dict(VPCRegion=ARN.get_region(), VPCId=vpc.vpc_id))
                self.zone = res["HostedZone"]
            else:
                msg = "Found {} private DNS zones; unable to determine zone to use. Set the dns.private_zone key in Aegea config" # noqa
                raise AegeaException(msg.format(len(private_zones)))
        else:
            raise AegeaException("Unable to determine DNS zone to use")
        self.zone_id = os.path.basename(self.zone["Id"])

    def update(self, names, values, action="UPSERT", record_type="CNAME", ttl=60):
        def format_rrs(name, value):
            return dict(Name=name + "." + self.zone["Name"],
                        Type=record_type,
                        TTL=ttl,
                        ResourceRecords=value if isinstance(value, (list, tuple)) else [{"Value": value}])
        if not isinstance(names, (list, tuple)):
            names, values = [names], [values]
        updates = [dict(Action=action, ResourceRecordSet=format_rrs(k, v)) for k, v in zip(names, values)]
        return clients.route53.change_resource_record_sets(HostedZoneId=self.zone_id,
                                                           ChangeBatch=dict(Changes=updates))

    def delete(self, name, value=None, record_type="CNAME", missing_ok=True):
        if value is None:
            res = clients.route53.list_resource_record_sets(HostedZoneId=self.zone_id,
                                                            StartRecordName=name + "." + self.zone["Name"],
                                                            StartRecordType=record_type)
            for rrs in res["ResourceRecordSets"]:
                if rrs["Name"] == name + "." + self.zone["Name"] and rrs["Type"] == record_type:
                    value = rrs["ResourceRecords"]
                    break
            else:
                msg = "Could not find {t} record {n} in Route53 zone {z}"
                msg = msg.format(t=record_type, n=name, z=self.zone["Name"])
                if missing_ok:
                    logger.warn(msg)
                    return
                else:
                    raise AegeaException(msg)
        return self.update(name, value, action="DELETE", record_type=record_type)

class ARN:
    fields = "arn partition service region account_id resource".split()
    _default_region, _default_account_id, _default_iam_username = None, None, None
    def __init__(self, arn="arn:aws::::", **kwargs):
        self.__dict__.update(dict(zip(self.fields, arn.split(":", 5)), **kwargs))
        if "region" not in kwargs and not self.region:
            self.region = self.get_region()
        if "account_id" not in kwargs and not self.account_id:
            self.account_id = self.get_account_id()

    @classmethod
    def get_region(cls):
        if cls._default_region is None:
            cls._default_region = botocore.session.Session().get_config_variable("region")
        return cls._default_region

    # TODO: for these two methods, introspect instance metadata without hanging if API not available
    @classmethod
    def get_account_id(cls):
        if cls._default_account_id is None:
            cls._default_account_id = clients.sts.get_caller_identity()["Account"]
        return cls._default_account_id

    @classmethod
    def get_iam_username(cls):
        if cls._default_iam_username is None:
            try:
                user = resources.iam.CurrentUser().user
                cls._default_iam_username = getattr(user, "name", ARN(user.arn).resource.split("/")[-1])
            except:
                try:
                    cls._default_iam_username = ARN(clients.sts.get_caller_identity()["Arn"]).resource.split("/")[-1]
                except:
                    cls._default_iam_username = "unknown"
        return cls._default_iam_username

    def __str__(self):
        return ":".join(getattr(self, field) for field in self.fields)

class IAMPolicyBuilder:
    def __init__(self, **kwargs):
        self.policy = dict(Version="2012-10-17", Statement=[])
        if kwargs:
            self.add_statement(**kwargs)

    def add_statement(self, principal=None, action=None, effect="Allow", resource=None):
        statement = dict(Action=[], Effect=effect)
        if principal:
            if not isinstance(principal, dict):
                principal = dict(AWS=principal)
            statement["Principal"] = principal
        self.policy["Statement"].append(statement)
        if action:
            for action in (action if isinstance(action, list) else [action]):
                self.add_action(action)
        if resource:
            for resource in (resource if isinstance(resource, list) else [resource]):
                self.add_resource(resource)

    def add_action(self, action):
        self.policy["Statement"][-1]["Action"].append(action)

    def add_resource(self, resource):
        self.policy["Statement"][-1].setdefault("Resource", [])
        self.policy["Statement"][-1]["Resource"].append(resource)

    def __str__(self):
        return json.dumps(self.policy)

def ensure_iam_role(name, policies=frozenset(), trust=frozenset()):
    return ensure_iam_entity(name, policies=policies, collection=resources.iam.roles,
                             constructor=resources.iam.create_role, RoleName=name,
                             AssumeRolePolicyDocument=get_assume_role_policy_doc(*trust))

def ensure_iam_group(name, policies=frozenset()):
    return ensure_iam_entity(name, policies=policies, collection=resources.iam.groups,
                             constructor=resources.iam.create_group, GroupName=name)

def ensure_iam_entity(iam_entity_name, policies, collection, constructor, **constructor_args):
    for entity in collection.all():
        if entity.name == iam_entity_name:
            break
    else:
        entity = constructor(**constructor_args)
    attached_policies = [policy.arn for policy in entity.attached_policies.all()]
    for policy in policies:
        if isinstance(policy, IAMPolicyBuilder):
            entity.Policy(__name__).put(PolicyDocument=str(policy))
        else:
            policy_arn = "arn:aws:iam::aws:policy/{}".format(policy)
            if policy_arn not in attached_policies:
                entity.attach_policy(PolicyArn="arn:aws:iam::aws:policy/{}".format(policy))
    # TODO: accommodate IAM eventual consistency
    return entity

def ensure_instance_profile(iam_role_name, policies=frozenset()):
    for instance_profile in resources.iam.instance_profiles.all():
        if instance_profile.name == iam_role_name:
            break
    else:
        instance_profile = resources.iam.create_instance_profile(InstanceProfileName=iam_role_name)
        clients.iam.get_waiter("instance_profile_exists").wait(InstanceProfileName=iam_role_name)
    role = ensure_iam_role(iam_role_name, policies=policies, trust=["ec2"])
    if not any(r.name == iam_role_name for r in instance_profile.roles):
        instance_profile.add_role(RoleName=role.name)
    return instance_profile

def encode_tags(tags):
    if isinstance(tags, (list, tuple)):
        tags = dict(tag.split("=", 1) for tag in tags)
    return [dict(Key=k, Value=v) for k, v in tags.items()]

def decode_tags(tags):
    return {tag["Key"]: tag["Value"] for tag in tags}

def add_tags(resource, dry_run=False, **tags):
    return resource.create_tags(Tags=encode_tags(tags), DryRun=dry_run)

def filter_by_tags(collection, **tags):
    return collection.filter(Filters=[dict(Name="tag:"+k, Values=[v]) for k, v in tags.items()])

def resolve_instance_id(name):
    filter_name = "dns-name" if name.startswith("ec2") and name.endswith("compute.amazonaws.com") else "tag:Name"
    if name.startswith("i-"):
        return name
    try:
        desc = clients.ec2.describe_instances(Filters=[dict(Name=filter_name, Values=[name])])
        return desc["Reservations"][0]["Instances"][0]["InstanceId"]
    except IndexError:
        raise AegeaException('Could not resolve "{}" to a known instance'.format(name))

def get_bdm(max_devices=12):
    # Note: d2.8xl and hs1.8xl have 24 devices
    return [dict(VirtualName="ephemeral" + str(i), DeviceName="xvd" + chr(ord("b")+i)) for i in range(max_devices)]

def get_metadata(path):
    return requests.get("http://169.254.169.254/latest/meta-data/{}".format(path)).content.decode()

def expect_error_codes(exception, *codes):
    if exception.response["Error"]["Code"] not in codes:
        raise

def resolve_ami(ami=None, **tags):
    if ami is None or not ami.startswith("ami-"):
        if ami is None:
            filters = dict(Owners=["self"], Filters=[dict(Name="state", Values=["available"])])
        else:
            filters = dict(Owners=["self"], Filters=[dict(Name="name", Values=[ami])])
        amis = resources.ec2.images.filter(**filters)
        if tags:
            amis = filter_by_tags(amis, **tags)
        amis = sorted(amis, key=lambda x: x.creation_date)
        if not amis:
            raise AegeaException("Could not resolve AMI {}".format(dict(tags, ami=ami)))
        ami = amis[-1].id
    return ami

offers_api = "https://pricing.us-east-1.amazonaws.com/offers/v1.0"

def region_name(region_id):
    region_names, region_ids = {}, {}
    from botocore import loaders
    for partition_data in loaders.create_loader().load_data("endpoints")["partitions"]:
        region_names.update({k: v["description"] for k, v in partition_data["regions"].items()})
        region_ids.update({v: k for k, v in region_names.items()})
    return region_names[region_id]

def get_pricing_data(offer, max_cache_age_days=30):
    from ... import config
    offer_filename = os.path.join(config.user_config_dir, offer + "_pricing_cache.json.gz")
    try:
        cache_date = datetime.fromtimestamp(os.path.getmtime(offer_filename))
        if cache_date < datetime.now() - timedelta(days=max_cache_age_days):
            raise Exception("Cache is too old, discard")
        with gzip.open(offer_filename) as fh:
            pricing_data = json.loads(fh.read().decode("utf-8"))
    except Exception as e:
        logger.info("Fetching pricing data for %s. This may take time.", offer)
        url = offers_api + "/aws/{offer}/current/index.json".format(offer=offer)
        pricing_data = requests.get(url).json()
        try:
            with gzip.open(offer_filename, "w") as fh:
                fh.write(json.dumps(pricing_data).encode("utf-8"))
        except Exception as e:
            print(e, file=sys.stderr)
    return pricing_data

def get_ec2_products(region=None, instance_type=None, tenancy="Shared", operating_system="Linux"):
    pricing_data = get_pricing_data("AmazonEC2")
    required_attributes = dict(tenancy=tenancy, operatingSystem=operating_system)
    if region:
        required_attributes.update(location=region_name(region))
    if instance_type:
        required_attributes.update(instanceType=instance_type)
    for product in pricing_data["products"].values():
        if not all(product["attributes"].get(i) == required_attributes[i] for i in required_attributes):
            continue
        if product["sku"] in pricing_data["terms"]["OnDemand"]:
            ondemand_terms = list(pricing_data["terms"]["OnDemand"][product["sku"]].values())[0]
            product.update(list(ondemand_terms["priceDimensions"].values())[0])
        yield product

def get_ondemand_price_usd(region, instance_type, **kwargs):
    for product in get_ec2_products(region=region, instance_type=instance_type, **kwargs):
        return product["pricePerUnit"]["USD"]

def get_iam_role_for_instance(instance):
    instance = resources.ec2.Instance(resolve_instance_id(instance))
    profile = resources.iam.InstanceProfile(ARN(instance.iam_instance_profile["Arn"]).resource.split("/")[1])
    assert len(profile.roles) <= 1
    return profile.roles[0] if profile.roles else None

def ensure_iam_policy(name, doc):
    try:
        return resources.iam.create_policy(PolicyName=name, PolicyDocument=str(doc))
    except ClientError as e:
        expect_error_codes(e, "EntityAlreadyExists")
        policy = resources.iam.Policy(str(ARN(service="iam", region="", resource="policy/" + name)))
        policy.create_version(PolicyDocument=str(doc), SetAsDefault=True)
        for version in policy.versions.all():
            if not version.is_default_version:
                version.delete()
        return policy

def get_elb_dns_aliases():
    dns_aliases = {}
    for zone in paginate(clients.route53.get_paginator("list_hosted_zones")):
        for rrs in paginate(clients.route53.get_paginator("list_resource_record_sets"), HostedZoneId=zone["Id"]):
            for record in rrs.get("ResourceRecords", [rrs.get("AliasTarget", {})]):
                value = record.get("Value", record.get("DNSName"))
                if value.endswith("elb.amazonaws.com") or value.endswith("elb.amazonaws.com."):
                    dns_aliases[value.rstrip(".").replace("dualstack.", "")] = rrs["Name"]
    return dns_aliases

ip_ranges_api = "https://ip-ranges.amazonaws.com/ip-ranges.json"

def get_public_ip_ranges(service="AMAZON", region=None):
    if region is None:
        region = ARN.get_region()
    ranges = requests.get(ip_ranges_api).json()["prefixes"]
    return [r for r in ranges if r["service"] == service and r["region"] == region]

def make_waiter(op, path, expected, matcher="path", delay=1, max_attempts=30):
    from botocore.waiter import Waiter, SingleWaiterConfig
    acceptor = dict(matcher=matcher, argument=path, expected=expected, state="success")
    waiter_cfg = dict(operation=op.__name__, delay=delay, maxAttempts=max_attempts, acceptors=[acceptor])
    return Waiter(op.__name__, SingleWaiterConfig(waiter_cfg), op)

def resolve_log_group(name):
    for log_group in paginate(clients.logs.get_paginator("describe_log_groups"), logGroupNamePrefix=name):
        if log_group["logGroupName"] == name:
            return log_group
    else:
        raise AegeaException("Log group {} not found".format(name))

def ensure_log_group(name):
    try:
        return resolve_log_group(name)
    except AegeaException:
        try:
            clients.logs.create_log_group(logGroupName=name)
        except clients.logs.exceptions.ResourceAlreadyExistsException:
            pass
        return resolve_log_group(name)

def get_cloudwatch_metric_stats(namespace, name, start_time=None, end_time=None, period=None, statistic="Average",
                                resource=None, **kwargs):
    start_time = datetime.utcnow() - period * 60 if start_time is None else start_time
    end_time = datetime.utcnow() if end_time is None else end_time
    cloudwatch = resources.cloudwatch if resource is None else resource
    metric = cloudwatch.Metric(namespace, name)
    get_stats_args = dict(StartTime=start_time, EndTime=end_time, Statistics=[statistic],
                          Dimensions=[dict(Name=k, Value=v) for k, v in kwargs.items()])
    if period is not None:
        get_stats_args.update(Period=period)
    return metric.get_statistics(**get_stats_args)
