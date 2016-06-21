from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json, io, gzip, time
import requests
from collections import OrderedDict
from warnings import warn
from datetime import datetime, timedelta

import botocore
from botocore.exceptions import ClientError
from botocore.utils import parse_to_aware_datetime

from ... import logger
from .. import constants, VerboseRepr, paginate
from ..exceptions import AegeaException
from ..crypto import get_public_key_from_pair
from ..compat import StringIO
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

def locate_ubuntu_ami(product="com.ubuntu.cloud:server:16.04:amd64", channel="releases", stream="released",
                      region="us-east-1", root_store="ssd", virt="hvm"):
    """
    Example: locate_ubuntu_ami(product="com.ubuntu.cloud.daily:server:16.04:amd64", channel="daily", stream="daily",
                               region="us-west-2")
    """
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
    version = max(versions)
    for ami in versions[version]["items"].values():
        if ami["crsn"] == region and ami["root_store"] == root_store and ami["virt"] == virt:
            return ami["id"]
    raise AegeaException("No AMI found for {} {} {} {} {}".format(product, version, region, root_store, virt))

def get_user_data(host_key=None, commands=None, packages=None, files=None):
    if packages is None:
        packages = []
    if commands is None:
        commands = []
    if files is None:
        files = []
    cloud_config_data = OrderedDict(packages=packages, write_files=files, runcmd=commands)
    if host_key is not None:
        buf = StringIO()
        host_key.write_private_key(buf)
        cloud_config_data["ssh_keys"] = dict(rsa_private=buf.getvalue(),
                                             rsa_public=get_public_key_from_pair(host_key))
    payload = "#cloud-config\n" + json.dumps(cloud_config_data)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="w") as gzfh:
        gzfh.write(payload.encode())
    return buf.getvalue()

def ensure_vpc():
    for vpc in resources.ec2.vpcs.filter(Filters=[dict(Name="isDefault", Values=["true"])]):
        break
    else:
        for vpc in resources.ec2.vpcs.all():
            break
        else:
            logger.info("Creating VPC")
            vpc = resources.ec2.create_vpc() # CidrBlock=...
            clients.ec2.get_waiter("vpc_available").wait(VpcIds=[vpc.id])
            vpc.modify_attribute(EnableDnsSupport={"Value": True})
            vpc.modify_attribute(EnableDnsHostnames={"Value": True})
    return vpc

def ensure_subnet(vpc):
    for subnet in vpc.subnets.all():
        break
    else:
        raise AegeaException("Not implemented")
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

def resolve_security_group(name, vpc):
    for security_group in vpc.security_groups.filter(GroupNames=[name]):
        assert security_group.group_name == name
        return security_group
    raise KeyError(name)

def ensure_security_group(name, vpc):
    try:
        security_group = resolve_security_group(name, vpc)
    except (ClientError, KeyError):
        logger.info("Creating security group %s for %s", name, vpc)
        security_group = vpc.create_security_group(GroupName=name, Description=name)
    ensure_ingress_rule(security_group, IpProtocol="tcp", FromPort=22, ToPort=22, CidrIp="0.0.0.0/0")
    return security_group

class DNSZone:
    def __init__(self, zone_name=None, use_unique_private_zone=True):
        if zone_name:
            self.zone = clients.route53.list_hosted_zones_by_name(DNSName=zone_name)["HostedZones"][0]
            assert self.zone["Name"] == zone_name + "."
        elif use_unique_private_zone:
            private_zones = []
            for zone in paginate(clients.route53.get_paginator('list_hosted_zones')):
                if zone.get("Config", {}).get("PrivateZone") is True:
                    private_zones.append(zone)
            if len(private_zones) == 1:
                self.zone = zone
            else:
                msg = "Found {} private DNS zones; unable to determine zone to use"
                raise AegeaException(msg.format(len(private_zones)))
        else:
            raise AegeaException("Unable to determine DNS zone to use")
        self.zone_id = os.path.basename(self.zone["Id"])

    def update(self, name, value, action="UPSERT", record_type="CNAME", ttl=60):
        if not isinstance(value, list):
            value = [{"Value": value}]
        dns_update = dict(Action=action,
                          ResourceRecordSet=dict(Name=name + "." + self.zone["Name"],
                                                 Type=record_type,
                                                 TTL=ttl,
                                                 ResourceRecords=value))
        clients.route53.change_resource_record_sets(HostedZoneId=self.zone_id,
                                                    ChangeBatch=dict(Changes=[dns_update]))

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
                    warn(msg)
                    return
                else:
                    raise AegeaException(msg)
        self.update(name, value, action="DELETE", record_type=record_type)

class ARN:
    fields = "arn partition service region account_id resource".split()
    def __init__(self, arn="arn:aws::::", **kwargs):
        self.__dict__.update(dict(zip(self.fields, arn.split(":", 5)), **kwargs))

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
            self.add_action(action)
        if resource:
            self.add_resource(resource)

    def add_action(self, action):
        self.policy["Statement"][-1]["Action"].append(action)

    def add_resource(self, resource):
        self.policy["Statement"][-1].setdefault("Resource", [])
        self.policy["Statement"][-1]["Resource"].append(resource)

    def __str__(self):
        return json.dumps(self.policy)

def ensure_iam_role(iam_role_name, policies=frozenset(), trust=frozenset()):
    for role in resources.iam.roles.all():
        if role.name == iam_role_name:
            break
    else:
        role = resources.iam.create_role(RoleName=iam_role_name,
                                         AssumeRolePolicyDocument=get_assume_role_policy_doc(*trust))
    attached_policies = [policy.arn for policy in role.attached_policies.all()]
    for policy in policies:
        policy_arn = "arn:aws:iam::aws:policy/{}".format(policy)
        if policy_arn not in attached_policies:
            role.attach_policy(PolicyArn="arn:aws:iam::aws:policy/{}".format(policy))
    # TODO: accommodate IAM eventual consistency
    return role

def ensure_instance_profile(iam_role_name, policies=frozenset()):
    for instance_profile in resources.iam.instance_profiles.all():
        if instance_profile.name == iam_role_name:
            break
    else:
        instance_profile = resources.iam.create_instance_profile(InstanceProfileName=iam_role_name)
        clients.iam.get_waiter('instance_profile_exists').wait(InstanceProfileName=iam_role_name)
    role = ensure_iam_role(iam_role_name, policies=policies, trust=["ec2"])
    if not any(r.name == iam_role_name for r in instance_profile.roles):
        instance_profile.add_role(RoleName=role.name)
    return instance_profile

def add_tags(resource, **tags):
    return resource.create_tags(Tags=[dict(Key=k, Value=v) for k, v in tags.items()])

#def filter_by_tags(collection, **tags):
#    return collection.filter(Filters=[dict(Name="tag:"+k, Values=[v]) for k, v in tags.items()])

def resolve_instance_id(name):
    if name.startswith("i-"):
        return name
    try:
        desc = clients.ec2.describe_instances(Filters=[dict(Name="tag:Name", Values=[name])])
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

def resolve_ami(ami=None):
    if ami is None or not ami.startswith("ami-"):
        if ami is None:
            filters = dict(Owners=["self"], Filters=[dict(Name="state", Values=["available"])])
        else:
            filters = dict(Owners=["self"], Filters=[dict(Name="name", Values=[ami])])
        amis = sorted(resources.ec2.images.filter(**filters), key=lambda x: x.creation_date)
        ami = amis[-1].id
    return ami

offers_api = "https://pricing.us-east-1.amazonaws.com/offers/v1.0"

def region_name(region_id):
    region_names, region_ids = {}, {}
    from botocore import loaders
    for partition_data in loaders.create_loader().load_data('endpoints')["partitions"]:
        region_names.update({k: v["description"] for k, v in partition_data["regions"].items()})
        region_ids.update({v: k for k, v in region_names.items()})
    return region_names[region_id]

def get_pricing_data(offer, max_cache_age_days=30):
    from ... import config
    offer_filename = os.path.join(os.path.dirname(config.config_files[1]), offer + "_pricing_cache.json.gz")
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
        ondemand_terms = list(pricing_data["terms"]["OnDemand"][product["sku"]].values())[0]
        product.update(list(ondemand_terms["priceDimensions"].values())[0])
        yield product

def get_ondemand_price_usd(region, instance_type, **kwargs):
    for product in get_ec2_products(region=region, instance_type=instance_type, **kwargs):
        return product["pricePerUnit"]["USD"]

class SpotFleetBuilder(VerboseRepr):
    # TODO: vivify from toolspec; vivify from SFR ID; update with incremental cores/memory requirements
    def __init__(self, launch_spec, cores=1, min_cores_per_instance=1, min_mem_per_core_gb=1.5, gpus_per_instance=0,
                 min_ephemeral_storage_gb=0, spot_price=None, duration_hours=None, client_token=None, dry_run=False):
        if spot_price is None:
            spot_price = 1
        if "SecurityGroupIds" in launch_spec:
            launch_spec["SecurityGroups"] = [dict(GroupId=i) for i in launch_spec["SecurityGroupIds"]]
            del launch_spec["SecurityGroupIds"]
        self.launch_spec = launch_spec
        self.cores = cores
        self.min_cores_per_instance = min_cores_per_instance
        self.min_ephemeral_storage_gb = min_ephemeral_storage_gb
        if min_cores_per_instance > cores:
            raise AegeaException("SpotFleetBuilder: min_cores_per_instance cannot exceed cores")
        self.min_mem_per_core_gb = min_mem_per_core_gb
        self.gpus_per_instance = gpus_per_instance
        self.dry_run = dry_run
        self.iam_fleet_role = ensure_iam_role("SpotFleet",
                                              policies=["service-role/AmazonEC2SpotFleetRole"],
                                              trust=["spotfleet"])
        self.spot_fleet_request_config = dict(SpotPrice=str(spot_price),
                                              TargetCapacity=cores,
                                              IamFleetRole=self.iam_fleet_role.arn)
        if client_token:
            self.spot_fleet_request_config.update(ClientToken=client_token)
        if duration_hours:
            deadline = datetime.utcnow().replace(microsecond=0) + timedelta(hours=duration_hours)
            self.spot_fleet_request_config.update(ValidUntil=deadline,
                                                  TerminateInstancesWithExpiration=True)

    def instance_types(self, max_overprovision=3, restrict_to_families=None):
        def compute_ephemeral_storage_gb(instance_data):
            if instance_data["storage"] == "EBS only":
                return 0
            count, size = [int(x) for x in instance_data["storage"].rstrip("SSD").rstrip("HDD").split("x")]
            return count * size

        max_cores = self.cores * max_overprovision
        max_mem_per_core = self.min_mem_per_core_gb * max_overprovision
        max_gpus = self.gpus_per_instance * max_overprovision
        for instance_type, instance_data in constants.get("instance_types").items():
            cores, gpus = int(instance_data["vcpu"]), int(instance_data["gpu"] or 0)
            mem_per_core = float(instance_data["memory"].rstrip(" GiB")) / cores
            if compute_ephemeral_storage_gb(instance_data) < self.min_ephemeral_storage_gb:
                continue
            if cores < self.min_cores_per_instance or cores > max_cores:
                continue
            if mem_per_core < self.min_mem_per_core_gb or mem_per_core > max_mem_per_core:
                continue
            if gpus < self.gpus_per_instance or gpus > max_gpus:
                continue
            if restrict_to_families and not any(instance_type.startswith(fam + ".") for fam in restrict_to_families):
                continue
            yield instance_type, int(instance_data["vcpu"])

    def launch_specs(self, **kwargs):
        for instance_type, weighted_capacity in self.instance_types(**kwargs):
            yield dict(self.launch_spec,
                       InstanceType=instance_type,
                       WeightedCapacity=weighted_capacity)

    def __call__(self, **kwargs):
        self.spot_fleet_request_config["LaunchSpecifications"] = list(self.launch_specs())
        logger.debug(self.spot_fleet_request_config)
        res = clients.ec2.request_spot_fleet(DryRun=self.dry_run,
                                             SpotFleetRequestConfig=self.spot_fleet_request_config,
                                             **kwargs)
        return res["SpotFleetRequestId"]
