from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys
from datetime import datetime

import boto3

from . import register_parser
from .util.printing import format_table, page_output
from .util.aws import ARN

def get_field(item, field):
    for element in field.split("."):
        try:
            item = getattr(item, element)
        except AttributeError:
            item = item.get(element)
    return item

def get_cell(resource, field):
    cell = get_field(resource, field)
    return ", ".join(i.name for i in cell.all()) if hasattr(cell, "all") else cell

def tabulate(collection, args):
    table = [[get_cell(i, f) for f in args.columns] for i in collection]
    if getattr(args, "sort_by", None):
        table = sorted(table, key=lambda x: x[args.columns.index(args.sort_by)])
    return format_table(table, column_names=args.columns, max_col_width=args.max_col_width)

def ls(args):
    ec2 = boto3.resource("ec2")
    for col in "tags", "launch_time":
        if col not in args.columns:
            args.columns.append(col)
    table = [[get_field(i, f) for f in args.columns] for i in ec2.instances.all()]
    table = sorted(table, key=lambda x: x[args.columns.index("launch_time")])
    for row in table:
        if "state" in args.columns:
            row[args.columns.index("state")] = row[args.columns.index("state")]["Name"]
        tags = {tag["Key"]: tag["Value"] for tag in row[args.columns.index("tags")]} if row[args.columns.index("tags")] else {}
        name = tags.get("Name", row[args.columns.index("id")])
        row[args.columns.index("tags")] = ", ".join("{}={}".format(k, v) for k, v in tags.items())
        row.insert(0, name)
    page_output(format_table(table, column_names=["name"] + args.columns, max_col_width=args.max_col_width))

parser = register_parser(ls, help='List EC2 instances')
parser.add_argument("--columns", nargs="+", default=["id", "state", "instance_type", "launch_time", "public_dns_name", "image_id", "tags"])

def users(args):
    iam = boto3.resource("iam")
    current_user = iam.CurrentUser()
    if "user_id" not in args.columns:
        args.columns.append("user_id")
    table = [[">>>" if i.user_id == current_user.user_id else ""] + [get_cell(i, f) for f in args.columns] for i in iam.users.all()]
    page_output(format_table(table, column_names=["cur"] + args.columns, max_col_width=args.max_col_width))

parser = register_parser(users, help='List IAM users')
parser.add_argument("--columns", nargs="+", default=["name", "user_id", "create_date", "password_last_used", "groups"])

def groups(args):
    page_output(tabulate(boto3.resource("iam").groups.all(), args))

parser = register_parser(groups, help='List IAM groups')
parser.add_argument("--columns", nargs="+", default=["name", "group_id", "create_date", "users"])

def roles(args):
    page_output(tabulate(boto3.resource("iam").roles.all(), args))

parser = register_parser(roles, help='List IAM roles')
parser.add_argument("--columns", nargs="+", default=["name", "role_id", "create_date", "instance_profiles"])

def volumes(args):
    ec2 = boto3.resource("ec2")
    table = [[get_cell(i, f) for f in args.columns] for i in ec2.volumes.all()]
    if "attachments" in args.columns:
        for row in table:
            row[args.columns.index("attachments")] = ", ".join(a["InstanceId"] for a in row[args.columns.index("attachments")])
    page_output(format_table(table, column_names=args.columns, max_col_width=args.max_col_width))

parser = register_parser(volumes, help='List EC2 EBS volumes')
parser.add_argument("--columns", nargs="+", default=["id", "size", "volume_type", "iops", "encrypted", "state", "create_time", "attachments", "availability_zone"])

def snapshots(args):
    account_id = ARN(boto3.resource("iam").CurrentUser().arn).account_id
    page_output(tabulate(boto3.resource("ec2").snapshots.filter(OwnerIds=[account_id]), args))

parser = register_parser(snapshots, help='List EC2 EBS snapshots')
parser.add_argument("--columns", nargs="+", default=["id", "description", "volume", "volume_size", "state", "progress", "encrypted", "owner_id", "start_time", "tags"])

def buckets(args):
    page_output(tabulate(boto3.resource("s3").buckets.all(), args))

parser = register_parser(buckets, help='List S3 buckets')
parser.add_argument("--columns", nargs="+", default=["name", "creation_date"])

def console(args):
    ec2 = boto3.resource("ec2")
    page_output(ec2.Instance(args.instance).console_output()['Output'])

parser = register_parser(console, help='Get console output for an EC2 instance')
parser.add_argument("instance")

def zones(args):
    table = []
    rrs_cols = ["Name", "Type", "TTL"]
    record_cols = ["Value"]
    route53 = boto3.client("route53")
    for page in route53.get_paginator('list_hosted_zones').paginate():
        for zone in page["HostedZones"]:
            if args.zones and zone["Name"] not in args.zones + [z + "." for z in args.zones]:
                continue
            for page2 in route53.get_paginator('list_resource_record_sets').paginate(HostedZoneId=zone["Id"]):
                for rrs in page2["ResourceRecordSets"]:
                    for record in rrs.get("ResourceRecords", []):
                        table.append([rrs.get(f) for f in rrs_cols] + [record.get(f) for f in record_cols] + [get_field(zone, "Config.PrivateZone")])
    page_output(format_table(table, column_names=rrs_cols + record_cols + ["Private"], max_col_width=args.max_col_width))

parser = register_parser(zones, help='List Route53 DNS zones')
parser.add_argument("zones", nargs='*')

def images(args):
    page_output(tabulate(boto3.resource("ec2").images.filter(Owners=["self"]), args))

parser = register_parser(images, help='List EC2 AMIs')
parser.add_argument("--columns", nargs="+", default=["id", "name", "description", "creation_date", "public", "virtualization_type", "state", "tags"])
parser.add_argument("--sort-by", default="creation_date")

def security_groups(args):
    page_output(tabulate(boto3.resource("ec2").security_groups.all(), args))

parser = register_parser(security_groups, help='List EC2 security groups')
parser.add_argument("--columns", nargs="+", default=["id", "group_name", "description", "ip_permissions", "ip_permissions_egress", "vpc_id"])

def logs(args):
    table = []
    group_cols = ["logGroupName"]
    stream_cols = ["logStreamName", "lastIngestionTime", "storedBytes"]
    logs = boto3.client("logs")
    for page in logs.get_paginator('describe_log_groups').paginate():
        for group in page["logGroups"]:
            if args.log_groups and group["logGroupName"] not in args.log_groups:
                continue
            for page2 in logs.get_paginator('describe_log_streams').paginate(logGroupName=group["logGroupName"]):
                for stream in page2["logStreams"]:
                    stream["lastIngestionTime"] = datetime.utcnow() - datetime.utcfromtimestamp(stream["lastIngestionTime"]/1000)
                    table.append([get_field(group, f) for f in group_cols] + [get_field(stream, f) for f in stream_cols])

#                    for page3 in logs.get_paginator('filter_log_events').paginate(logGroupName=group["logGroupName"]):
#                        for event in page3["events"]:
#                            print(event["timestamp"], event["message"])
    page_output(format_table(table, column_names=group_cols + stream_cols, max_col_width=args.max_col_width))

parser = register_parser(logs, help='List CloudWatch Logs groups and streams')
parser.add_argument("log_groups", nargs="*")

def clusters(args):
    ecs = boto3.client('ecs')
    cluster_arns = sum([p["clusterArns"] for p in ecs.get_paginator('list_clusters').paginate()], [])
    page_output(tabulate(ecs.describe_clusters(clusters=cluster_arns)["clusters"], args))

parser = register_parser(clusters, help='List ECS clusters')
parser.add_argument("--columns", nargs="+", default=["clusterName", "clusterArn", "status", "registeredContainerInstancesCount", "runningTasksCount", "pendingTasksCount"])

def tasks(args):
    ecs = boto3.client('ecs')
    cluster_arns = sum([p["clusterArns"] for p in ecs.get_paginator('list_clusters').paginate()], [])
    table = []
    for cluster_arn in cluster_arns:
        task_arns = sum([p["taskArns"] for p in ecs.get_paginator('list_tasks').paginate(cluster=cluster_arn)], [])
        if task_arns:
            for task in ecs.describe_tasks(cluster=cluster_arn, tasks=task_arns)["tasks"]:
                table.append([get_field(task, f) for f in args.columns])
    page_output(format_table(table, column_names=args.columns, max_col_width=args.max_col_width))

parser = register_parser(tasks, help='List ECS tasks')
parser.add_argument("--columns", nargs="+", default=["taskArn", "taskDefinitionArn", "clusterArn", "lastStatus", "desiredStatus", "createdAt", "overrides"])

def sirs(args):
    page_output(tabulate(boto3.client('ec2').describe_spot_instance_requests()['SpotInstanceRequests'], args))

parser = register_parser(sirs, help='List EC2 spot instance requests')
parser.add_argument("--columns", nargs="+", default=["SpotInstanceRequestId", "CreateTime", "SpotPrice", "LaunchSpecification.InstanceType", "State", "Status.Message", "InstanceId"])

def key_pairs(args):
    page_output(tabulate(boto3.resource("ec2").key_pairs.all(), args))

parser = register_parser(key_pairs, help='List EC2 SSH key pairs')
parser.add_argument("--columns", nargs="+", default=["name", "key_fingerprint"])

def subnets(args):
    page_output(tabulate(boto3.resource("ec2").subnets.all(), args))

parser = register_parser(subnets, help='List EC2 VPCs and subnets')
parser.add_argument("--columns", nargs="+", default=["id", "vpc_id", "availability_zone", "cidr_block", "default_for_az", "map_public_ip_on_launch", "state", "tags"])
