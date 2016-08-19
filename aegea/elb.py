"""
Manage AWS EC2 Elastic Load Balancers (ELBs) and Application Load Balancers (ALBs).
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse

from .ls import register_parser, register_listing_parser
from .util import Timestamp, paginate, hashabledict
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.exceptions import AegeaException
from .util.aws import (ARN, resources, clients, resolve_instance_id, resolve_security_group, get_elb_dns_aliases,
                       DNSZone, ensure_vpc)

def elb(args):
    elb_parser.print_help()

elb_parser = register_parser(elb, help='Manage Elastic Load Balancers', description=__doc__,
                             formatter_class=argparse.RawTextHelpFormatter)

def ls(args):
    table = []
    dns_aliases = get_elb_dns_aliases()
    for row in paginate(clients.elb.get_paginator('describe_load_balancers')):
        row.update(alias=dns_aliases.get(row["DNSName"]), type="ELB")
        instances = clients.elb.describe_instance_health(LoadBalancerName=row["LoadBalancerName"])["InstanceStates"]
        table.extend([dict(row, **instance) for instance in instances] if instances else [row])
    for row in clients.elbv2.describe_load_balancers()["LoadBalancers"]:
        row.update(alias=dns_aliases.get(row["DNSName"]), type="ALB")
        target_groups = clients.elbv2.describe_target_groups(LoadBalancerArn=row["LoadBalancerArn"])["TargetGroups"]
        for tg in target_groups:
            targets = get_targets(tg)
            table.extend([dict(row, **target) for target in targets] if targets else [row])
    page_output(tabulate(table, args))

parser = register_listing_parser(ls, parent=elb_parser)

def get_target_group(alb_name, target_group_name):
    alb = clients.elbv2.describe_load_balancers(Names=[alb_name])["LoadBalancers"][0]
    target_groups = clients.elbv2.describe_target_groups(LoadBalancerArn=alb["LoadBalancerArn"])["TargetGroups"]
    for target_group in target_groups:
        if target_group["TargetGroupName"] == target_group_name:
            return dict(alb, **target_group)
    m = "Target group {} not found in {} (target groups found: {})"
    raise AegeaException(m.format(target_group_name, alb_name, ", ".join(t["TargetGroupName"] for t in target_groups)))

def get_targets(target_group):
    res = clients.elbv2.describe_target_health(TargetGroupArn=target_group["TargetGroupArn"])
    return res["TargetHealthDescriptions"]

def register(args):
    if args.type == "ELB":
        instances = [dict(InstanceId=i) for i in args.instances]
        res = clients.elb.register_instances_with_load_balancer(LoadBalancerName=args.elb_name, Instances=instances)
        return dict(registered=instances, current=res["Instances"])
    elif args.type == "ALB":
        target_group = get_target_group(args.elb_name, args.target_group)
        instances = [dict(Id=i, Port=target_group.get("Port", args.instance_port)) for i in args.instances]
        clients.elbv2.register_targets(TargetGroupArn=target_group["TargetGroupArn"], Targets=instances)
        return dict(registered=instances, current=[t["Target"] for t in get_targets(target_group)])

parser_register = register_parser(register, parent=elb_parser, help="Add EC2 instances to an ELB")

def deregister(args):
    if args.type == "ELB":
        instances = [dict(InstanceId=i) for i in args.instances]
        res = clients.elb.deregister_instances_from_load_balancer(LoadBalancerName=args.elb_name, Instances=instances)
        return dict(deregistered=instances, current=res["Instances"])
    elif args.type == "ALB":
        target_group = get_target_group(args.elb_name, args.target_group)
        instances = [dict(Id=i, Port=target_group.get("Port", args.instance_port)) for i in args.instances]
        clients.elbv2.deregister_targets(TargetGroupArn=target_group["TargetGroupArn"], Targets=instances)
        return dict(deregistered=instances, current=[t["Target"] for t in get_targets(target_group)])

parser_deregister = register_parser(deregister, parent=elb_parser, help="Remove EC2 instances from an ELB")

def replace(args):
    result = register(args)
    old_instances = set(hashabledict(d) for d in result["current"]) - set(hashabledict(d) for d in result["registered"])
    if old_instances:
        args.instances = [i.get("Id", i.get("InstanceId")) for i in old_instances]
        result.update(deregister(args))
    return result

parser_replace = register_parser(replace, parent=elb_parser,
                                 help="Replace all EC2 instances in an ELB with the ones given")

def create(args):
    for zone in paginate(clients.route53.get_paginator('list_hosted_zones')):
        if args.dns_alias.endswith("." + zone["Name"].rstrip(".")):
            break
    else:
        raise AegeaException("Unable to find Route53 DNS zone for {}".format(args.dns_alias))
    for cert in paginate(clients.acm.get_paginator('list_certificates')):
        if cert["DomainName"] in (args.dns_alias, ".".join(["*"] + args.dns_alias.split(".")[1:])):
            break
    else:
        raise AegeaException("Unable to find ACM certificate for {}".format(args.dns_alias))
    azs = [az["ZoneName"] for az in clients.ec2.describe_availability_zones()["AvailabilityZones"]]
    if args.type == "ELB":
        listener = dict(Protocol="https",
                        LoadBalancerPort=443,
                        SSLCertificateId=cert["CertificateArn"],
                        InstanceProtocol="http",
                        InstancePort=args.instance_port or 80)
        elb = clients.elb.create_load_balancer(LoadBalancerName=args.elb_name,
                                               Listeners=[listener],
                                               AvailabilityZones=azs,
                                               SecurityGroups=[sg.id for sg in args.security_groups])
    elif args.type == "ALB":
        vpc = ensure_vpc()
        res = clients.elbv2.create_load_balancer(Name=args.elb_name,
                                                 Subnets=[subnet.id for subnet in vpc.subnets.all()],
                                                 SecurityGroups=[sg.id for sg in args.security_groups])
        elb = res["LoadBalancers"][0]
        res = clients.elbv2.create_target_group(Name=args.target_group,
                                                Protocol="HTTP",
                                                Port=args.instance_port,
                                                VpcId=vpc.id)
        target_group = res["TargetGroups"][0]
        listener_params = dict(Protocol="HTTPS",
                               Port=443,
                               Certificates=[dict(CertificateArn=cert["CertificateArn"])],
                               DefaultActions=[dict(Type="forward",
                                                    TargetGroupArn=target_group["TargetGroupArn"])])
        res = clients.elbv2.describe_listeners(LoadBalancerArn=elb["LoadBalancerArn"])
        if res["Listeners"]:
            res = clients.elbv2.modify_listener(ListenerArn=res["Listeners"][0]["ListenerArn"], **listener_params)
        else:
            res = clients.elbv2.create_listener(**listener_params)
        listener = res["Listeners"][0]
        if args.path_pattern:
            rules = clients.elbv2.describe_rules(ListenerArn=listener["ListenerArn"])["Rules"]
            clients.elbv2.create_rule(ListenerArn=listener["ListenerArn"],
                                      Conditions=[dict(Field="path-pattern", Values=[args.path_pattern])],
                                      Actions=[dict(Type="forward", TargetGroupArn=target_group["TargetGroupArn"])],
                                      Priority=len(rules))
    register(args)
    DNSZone(zone["Name"]).update(args.dns_alias.replace("." + zone["Name"].rstrip("."), ""), elb["DNSName"])
    return dict(elb_name=args.elb_name, dns_name=elb["DNSName"], dns_alias=args.dns_alias)

parser_create = register_parser(create, parent=elb_parser, help="Create a new ELB")
parser_create.add_argument("--security-groups", nargs="+", type=resolve_security_group, required=True, help="""
Security groups to be used by the ELB's internal interface.
Security groups must allow TCP traffic to flow between the ELB and the instances on INSTANCE_PORT.""")
parser_create.add_argument("--dns-alias", required=True, help="Fully qualified DNS name that will point to the ELB")
parser_create.add_argument("--path-pattern")

for parser in parser_register, parser_deregister, parser_replace, parser_create:
    parser.add_argument("elb_name")
    parser.add_argument("instances", nargs="+", type=resolve_instance_id)
    parser.add_argument("--type", choices={"ELB", "ALB"}, default="ALB")
    parser.add_argument("--target-group", default="aegea-default-tg")
    parser.add_argument("--instance-port", type=int, default=80)
