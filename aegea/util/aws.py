from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json, io
import requests
from collections import OrderedDict
from warnings import warn

import boto3

from .. import logger
from .crypto import get_public_key_from_pair

def get_assume_role_policy_doc(service="lambda"):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "{}.amazonaws.com".format(service)
                },
                "Action": "sts:AssumeRole"
            }
        ]
    })

def locate_ubuntu_ami(product="com.ubuntu.cloud:server:16.04:amd64", region="us-east-1", root_store="ebs", virt="hvm"):
    partition = "aws"
    if region.startswith("cn-"):
        partition = "aws-cn"
    elif region.startswith("us-gov-"):
        partition = "aws-govcloud"
    if partition not in {"aws", "aws-cn", "aws-govcloud"}:
        raise Exception("Unrecognized partition {}".format(partition))
    manifest_url = "https://cloud-images.ubuntu.com/releases/streams/v1/com.ubuntu.cloud:released:{partition}.json"
    manifest_url = manifest_url.format(partition=partition)
    manifest = requests.get(manifest_url).json()
    if product not in manifest["products"]:
        raise Exception("Ubuntu version {} not found in Ubuntu cloud image manifest".format(product))
    versions = manifest["products"][product]["versions"]
    version = max(versions)
    for ami in versions[version]["items"].values():
        if ami["crsn"] == region and ami["root_store"] == root_store and ami["virt"] == virt:
            return ami["id"]
    raise Exception("No AMI found for {} {} {} {} {}".format(product, version, region, root_store, virt))

def get_user_data(host_key, commands=None, packages=None, files=None):
    if packages is None:
        packages = []
    if commands is None:
        commands = []
    if files is None:
        files = []
    buf = io.StringIO()
    host_key.write_private_key(buf)
    cloud_config_data = OrderedDict(ssh_keys=dict(rsa_private=buf.getvalue(),
                                                  rsa_public=get_public_key_from_pair(host_key)),
                                    packages=packages,
                                    write_files=files,
                                    runcmd=commands)
    return "#cloud-config\n" + json.dumps(cloud_config_data)

def ensure_vpc():
    ec2 = boto3.resource("ec2")
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
        raise Exception("Not implemented")
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

def ensure_security_group(name, vpc):
    for security_group in vpc.security_groups.all():
        if security_group.group_name == name:
            break
    else:
        logger.info("Creating security group %s for %s", name, vpc)
        security_group = vpc.create_security_group(GroupName=name, Description=name)
    ensure_ingress_rule(security_group, IpProtocol="tcp", FromPort=22, ToPort=22, CidrIp="0.0.0.0/0")
    return security_group

class DNSZone:
    def __init__(self, zone_name):
        self.route53 = boto3.client("route53")
        self.zone_name = zone_name
        self.zone = self.route53.list_hosted_zones_by_name(DNSName=zone_name)["HostedZones"][0]
        self.zone_id = os.path.basename(self.zone["Id"])
        assert self.zone["Name"] == zone_name + "."

    def update(self, name, value, action="UPSERT", record_type="CNAME", ttl=60):
        if not isinstance(value, list):
            value = [{"Value": value}]
        dns_update = dict(Action=action,
                          ResourceRecordSet=dict(Name=name + "." + self.zone_name + ".",
                                                 Type=record_type,
                                                 TTL=ttl,
                                                 ResourceRecords=value))
        self.route53.change_resource_record_sets(HostedZoneId=self.zone_id,
                                                 ChangeBatch=dict(Changes=[dns_update]))

    def delete(self, name, value=None, record_type="CNAME", missing_ok=True):
        if value is None:
            res = self.route53.list_resource_record_sets(HostedZoneId=self.zone_id,
                                                         StartRecordName=name + "." + self.zone_name + ".",
                                                         StartRecordType=record_type)
            for rrs in res["ResourceRecordSets"]:
                if rrs["Name"] == name + "." + self.zone_name + "." and rrs["Type"] == record_type:
                    value = rrs["ResourceRecords"]
                    break
            else:
                msg = "Could not find {t} {n} in Route53 zone {z}".format(t=record_type, n=name, z=self.zone_name)
                if missing_ok:
                    warn(msg)
                    return
                else:
                    raise Exception(msg)
        self.update(name, value, action="DELETE", record_type=record_type)

class ARN:
    fields = "arn partition service region account_id resource".split()
    def __init__(self, arn):
        self.__dict__.update(dict(zip(self.fields, arn.split(":", 5))))

    def __str__(self):
        return ":".join(getattr(self, field) for field in self.fields)

def ensure_iam_role(iam_role_name):
    iam = boto3.resource("iam")
    for role in iam.roles.all():
        if role.name == iam_role_name:
            break
    else:
        role = iam.create_role(RoleName=iam_role_name, AssumeRolePolicyDocument=get_assume_role_policy_doc("ec2"))
    role.attach_policy(PolicyArn="arn:aws:iam::aws:policy/IAMReadOnlyAccess")
    return role

def ensure_instance_profile(iam_role_name):
    iam = boto3.resource("iam")
    for instance_profile in iam.instance_profiles.all():
        if instance_profile.name == iam_role_name:
            break
    else:
        instance_profile = iam.create_instance_profile(InstanceProfileName=iam_role_name)
    if not any(role.name == iam_role_name for role in instance_profile.roles):
        role = ensure_iam_role(iam_role_name)
        instance_profile.add_role(RoleName=role.name)
    return instance_profile
