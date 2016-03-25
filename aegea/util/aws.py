from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json, io, gzip, time
import requests
from collections import OrderedDict
from warnings import warn
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import ClientError
from botocore.utils import parse_to_aware_datetime

from .exceptions import AegeaException
from .. import logger, config
from .crypto import get_public_key_from_pair
from .compat import StringIO

def get_assume_role_policy_doc(*services):
    p = IAMPolicyBuilder()
    for service in services:
        p.add_statement(principal={"Service": service + ".amazonaws.com"}, action="sts:AssumeRole")
    return json.dumps(p.policy)

def locate_ubuntu_ami(product="com.ubuntu.cloud:server:16.04:amd64", region="us-east-1", root_store="ebs", virt="hvm"):
    partition = "aws"
    if region.startswith("cn-"):
        partition = "aws-cn"
    elif region.startswith("us-gov-"):
        partition = "aws-govcloud"
    if partition not in {"aws", "aws-cn", "aws-govcloud"}:
        raise AegeaException("Unrecognized partition {}".format(partition))
    manifest_url = "https://cloud-images.ubuntu.com/releases/streams/v1/com.ubuntu.cloud:released:{partition}.json"
    manifest_url = manifest_url.format(partition=partition)
    manifest = requests.get(manifest_url).json()
    if product not in manifest["products"]:
        raise AegeaException("Ubuntu version {} not found in Ubuntu cloud image manifest".format(product))
    versions = manifest["products"][product]["versions"]
    version = max(versions)
    for ami in versions[version]["items"].values():
        if ami["crsn"] == region and ami["root_store"] == root_store and ami["virt"] == virt:
            return ami["id"]
    raise AegeaException("No AMI found for {} {} {} {} {}".format(product, version, region, root_store, virt))

def get_user_data(host_key, commands=None, packages=None, files=None):
    if packages is None:
        packages = []
    if commands is None:
        commands = []
    if files is None:
        files = []
    buf = StringIO()
    host_key.write_private_key(buf)
    cloud_config_data = OrderedDict(ssh_keys=dict(rsa_private=buf.getvalue(),
                                                  rsa_public=get_public_key_from_pair(host_key)),
                                    packages=packages,
                                    write_files=files,
                                    runcmd=commands)
    return "#cloud-config\n" + json.dumps(cloud_config_data)

def ensure_vpc():
    ec2 = boto3.resource("ec2")
    for vpc in ec2.vpcs.filter(Filters=[dict(Name="isDefault", Values=["true"])]):
        break
    else:
        for vpc in ec2.vpcs.all():
            break
        else:
            logger.info("Creating VPC")
            vpc = ec2.create_vpc() # CidrBlock=...
            ec2.meta.client.get_waiter("vpc_available").wait(VpcIds=[vpc.id])
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
        self.route53 = boto3.client("route53")
        if zone_name:
            self.zone = self.route53.list_hosted_zones_by_name(DNSName=zone_name)["HostedZones"][0]
            assert self.zone["Name"] == zone_name + "."
        elif use_unique_private_zone:
            private_zones = []
            for page in self.route53.get_paginator('list_hosted_zones').paginate():
                for zone in page["HostedZones"]:
                    if zone.get("Config", {}).get("PrivateZone") is True:
                        private_zones.append(zone)
            if len(private_zones) == 1:
                self.zone = zone
            else:
                raise AegeaException("Found {} private DNS zones; unable to determine zone to use".format(len(private_zones)))
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
        self.route53.change_resource_record_sets(HostedZoneId=self.zone_id,
                                                 ChangeBatch=dict(Changes=[dns_update]))

    def delete(self, name, value=None, record_type="CNAME", missing_ok=True):
        if value is None:
            res = self.route53.list_resource_record_sets(HostedZoneId=self.zone_id,
                                                         StartRecordName=name + "." + self.zone["Name"],
                                                         StartRecordType=record_type)
            for rrs in res["ResourceRecordSets"]:
                if rrs["Name"] == name + "." + self.zone["Name"] and rrs["Type"] == record_type:
                    value = rrs["ResourceRecords"]
                    break
            else:
                msg = "Could not find {t} record {n} in Route53 zone {z}".format(t=record_type, n=name, z=self.zone["Name"])
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

def ensure_iam_role(iam_role_name, policies=frozenset(), trusted_services=frozenset("ec2")):
    iam = boto3.resource("iam")
    for role in iam.roles.all():
        if role.name == iam_role_name:
            break
    else:
        role = iam.create_role(RoleName=iam_role_name, AssumeRolePolicyDocument=get_assume_role_policy_doc(*trusted_services))
    for policy in policies:
        # TODO: enumerate policies to avoid requiring IAM write access
        role.attach_policy(PolicyArn="arn:aws:iam::aws:policy/{}".format(policy))
    # TODO: accommodate IAM eventual consistency (role waiter)
    return role

def ensure_instance_profile(iam_role_name, policies=frozenset()):
    iam = boto3.resource("iam")
    for instance_profile in iam.instance_profiles.all():
        if instance_profile.name == iam_role_name:
            break
    else:
        instance_profile = iam.create_instance_profile(InstanceProfileName=iam_role_name)
        iam.meta.client.get_waiter('instance_profile_exists').wait(InstanceProfileName=iam_role_name)
    role = ensure_iam_role(iam_role_name, policies=policies)
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
    ec2 = boto3.resource("ec2")
    try:
        desc = ec2.meta.client.describe_instances(Filters=[dict(Name="tag:Name", Values=[name])])
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
    ec2 = boto3.resource("ec2")
    if ami is None or not ami.startswith("ami-"):
        if ami is None:
            filters = dict(Owners=["self"], Filters=[dict(Name="state", Values=["available"])])
        else:
            filters = dict(Owners=["self"], Filters=[dict(Name="name", Values=[ami])])
        amis = sorted(ec2.images.filter(**filters), key=lambda x: x.creation_date)
        ami = amis[-1].id
    return ami

offers_api = "https://pricing.us-east-1.amazonaws.com/offers/v1.0"
region_ids = {
    "US East (N. Virginia)": "us-east-1",
    "US West (N. California)": "us-west-1",
    "US West (Oregon)": "us-west-2",
    "EU (Ireland)": "eu-west-1",
    "EU (Frankfurt)": "eu-central-1",
    "Asia Pacific (Tokyo)": "ap-northeast-1",
    "Asia Pacific (Seoul)": "ap-northeast-2",
    "Asia Pacific (Singapore)": "ap-southeast-1",
    "Asia Pacific (Sydney)": "ap-southeast-2",
    "South America (Sao Paulo)": "sa-east-1",
    "AWS GovCloud (US)": "us-gov-west-1",
}
region_names = {v: k for k, v in region_ids.items()}

def get_pricing_data(offer, max_cache_age_days=30):
    offer_filename = os.path.join(config._config_dir, offer + "_pricing_cache.json.gz")
    try:
        if datetime.fromtimestamp(os.path.getmtime(offer_filename)) < datetime.now() - timedelta(days=max_cache_age_days):
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

def get_ondemand_price_usd(region, instance_type):
    pricing_data = get_pricing_data("AmazonEC2")
    for product in pricing_data["products"].values():
        required_attributes = dict(location=region_names[region],
                                   tenancy="Shared",
                                   operatingSystem="Linux",
                                   instanceType=instance_type)
        if not all(product["attributes"].get(i) == required_attributes[i] for i in required_attributes):
            continue
        ondemand_terms = list(pricing_data["terms"]["OnDemand"][product["sku"]].values())[0]
        product.update(list(ondemand_terms["priceDimensions"].values())[0])
        return product["pricePerUnit"]["USD"]
