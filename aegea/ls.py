from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys
from datetime import datetime

import boto3

from . import register_parser
from .util import parse_time_input
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.aws import ARN, resolve_instance_id

def register_listing_parser(function, **kwargs):
    parser = register_parser(function, **kwargs)
    parser.add_argument("--filter", nargs="+", default=[], help="Filter(s) to apply to output, e.g. --filter state=available")
    parser.add_argument("--tag", nargs="+", default=[], help="Tag(s) to filter output by, e.g. --tag Owner=bezos")
    return parser

def filter_collection(collection, args):
    filters = []
    # TODO: shlex?
    for f in getattr(args, "filter", []):
        name, value = f.split("=", 1)
        filters.append(dict(Name=name, Values=[value]))
    for t in getattr(args, "tag", []):
        name, value = t.split("=", 1)
        filters.append(dict(Name="tag:" + name, Values=[value]))
    return collection.filter(Filters=filters)

def filter_and_tabulate(collection, args, **kwargs):
    return tabulate(filter_collection(collection, args), args, **kwargs)

def ls(args):
    ec2 = boto3.resource("ec2")
    for col in "tags", "launch_time":
        if col not in args.columns:
            args.columns.append(col)
    def add_name(instance):
        instance.name = instance.id
        for tag in instance.tags or []:
            if tag["Key"] == "Name":
                instance.name = tag["Value"]
        return instance
    instances = [add_name(i) for i in filter_collection(ec2.instances, args)]
    args.columns = ["name"] + args.columns
    page_output(tabulate(instances, args, cell_transforms={"state": lambda x: x["Name"], "iam_instance_profile": lambda x: x.get("Arn", "").split("/")[-1] if x else None}))

parser = register_listing_parser(ls, help='List EC2 instances')
parser.add_argument("--columns", nargs="+")
parser.add_argument("--sort-by")

def users(args):
    iam = boto3.resource("iam")
    current_user = iam.CurrentUser()
    if "user_id" not in args.columns:
        args.columns.append("user_id")
    table = [[">>>" if i.user_id == current_user.user_id else ""] + [get_cell(i, f) for f in args.columns] for i in iam.users.all()]
    page_output(format_table(table, column_names=["cur"] + args.columns, max_col_width=args.max_col_width))

parser = register_parser(users, help='List IAM users')
parser.add_argument("--columns", nargs="+")

def groups(args):
    page_output(tabulate(boto3.resource("iam").groups.all(), args))

parser = register_parser(groups, help='List IAM groups')
parser.add_argument("--columns", nargs="+")

def roles(args):
    page_output(tabulate(boto3.resource("iam").roles.all(), args))

parser = register_parser(roles, help='List IAM roles')
parser.add_argument("--columns", nargs="+")

def policies(args):
    page_output(tabulate(boto3.resource("iam").policies.all(), args))

parser = register_parser(policies, help='List IAM policies')
parser.add_argument("--columns", nargs="+")
parser.add_argument("--sort-by")

def volumes(args):
    ec2 = boto3.resource("ec2")
    table = [[get_cell(i, f) for f in args.columns] for i in filter_collection(ec2.volumes, args)]
    if "attachments" in args.columns:
        for row in table:
            row[args.columns.index("attachments")] = ", ".join(a["InstanceId"] for a in row[args.columns.index("attachments")])
    page_output(format_table(table, column_names=args.columns, max_col_width=args.max_col_width))

parser = register_listing_parser(volumes, help='List EC2 EBS volumes')
parser.add_argument("--columns", nargs="+")

def snapshots(args):
    account_id = ARN(boto3.resource("iam").CurrentUser().arn).account_id
    page_output(filter_and_tabulate(boto3.resource("ec2").snapshots.filter(OwnerIds=[account_id]), args))

parser = register_listing_parser(snapshots, help='List EC2 EBS snapshots')
parser.add_argument("--columns", nargs="+")

def buckets(args):
    page_output(filter_and_tabulate(boto3.resource("s3").buckets, args))

parser = register_listing_parser(buckets, help='List S3 buckets')
parser.add_argument("--columns", nargs="+")

def console(args):
    ec2 = boto3.resource("ec2")
    instance_id = resolve_instance_id(args.instance)
    err = '[No console output received for {}. Console output may lag by several minutes.]'.format(instance_id)
    page_output(ec2.Instance(instance_id).console_output().get('Output', err))

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
    page_output(filter_and_tabulate(boto3.resource("ec2").images.filter(Owners=["self"]), args))

parser = register_listing_parser(images, help='List EC2 AMIs')
parser.add_argument("--columns", nargs="+")
parser.add_argument("--sort-by")

def security_groups(args):
    page_output(filter_and_tabulate(boto3.resource("ec2").security_groups, args))

parser = register_listing_parser(security_groups, help='List EC2 security groups')
parser.add_argument("--columns", nargs="+")

def logs(args):
    logs = boto3.client("logs")
    if args.log_group and args.log_stream:
        args.pattern = None
        return grep(args)
    table = []
    group_cols = ["logGroupName"]
    stream_cols = ["logStreamName", "lastIngestionTime", "storedBytes"]
    cols = group_cols + stream_cols
    for page in logs.get_paginator('describe_log_groups').paginate():
        for group in page["logGroups"]:
            if args.log_group and group["logGroupName"] != args.log_group:
                continue
            n = 0
            for page2 in logs.get_paginator('describe_log_streams').paginate(logGroupName=group["logGroupName"], orderBy="LastEventTime", descending=True):
                for stream in page2["logStreams"]:
                    stream["lastIngestionTime"] = datetime.utcnow().replace(microsecond=0) - datetime.utcfromtimestamp(stream.get("lastIngestionTime", 0)//1000)
                    table.append([get_field(group, f) for f in group_cols] + [get_field(stream, f) for f in stream_cols])
                    n += 1
                    if n >= args.max_streams_per_group:
                        break
                if n >= args.max_streams_per_group:
                    break
    table = sorted(table, key=lambda x: x[cols.index(args.sort_by)], reverse=True)
    page_output(format_table(table, column_names=cols, max_col_width=args.max_col_width))

parser = register_parser(logs, help='List CloudWatch Logs groups and streams')
parser.add_argument("--max-streams-per-group", "-n", type=int, default=8)
parser.add_argument("--sort-by", default="lastIngestionTime")
parser.add_argument("log_group", nargs="?")
parser.add_argument("log_stream", nargs="?")

def grep(args):
    logs = boto3.client("logs")
    filter_args = dict(logGroupName=args.log_group)
    if args.log_stream:
        filter_args.update(logStreamNames=[args.log_stream])
    if args.pattern:
        filter_args.update(filterPattern=args.pattern)
    if args.start_time:
        filter_args.update(startTime=int(args.start_time.timestamp() * 1000))
    if args.end_time:
        filter_args.update(endTime=int(args.end_time.timestamp() * 1000))
    for page in logs.get_paginator('filter_log_events').paginate(**filter_args):
        for event in page["events"]:
            print(event["timestamp"], event["message"])

parser = register_parser(grep, help='Filter and print events in a CloudWatch Logs stream or group of streams')
parser.add_argument("pattern")
parser.add_argument("log_group")
parser.add_argument("log_stream", nargs="?")
parser.add_argument("--start-time", type=parse_time_input)
parser.add_argument("--end-time", type=parse_time_input)

def clusters(args):
    ecs = boto3.client('ecs')
    cluster_arns = sum([p["clusterArns"] for p in ecs.get_paginator('list_clusters').paginate()], [])
    page_output(tabulate(ecs.describe_clusters(clusters=cluster_arns)["clusters"], args))

parser = register_parser(clusters, help='List ECS clusters')
parser.add_argument("--columns", nargs="+")

def tasks(args):
    ecs = boto3.client('ecs')
    cluster_arns = sum([p["clusterArns"] for p in ecs.get_paginator('list_clusters').paginate()], [])
    table = []
    for cluster_arn in cluster_arns:
        list_tasks_args = dict(cluster=cluster_arn, desiredStatus=args.desired_status)
        task_arns = sum([p["taskArns"] for p in ecs.get_paginator('list_tasks').paginate(**list_tasks_args)], [])
        if task_arns:
            for task in ecs.describe_tasks(cluster=cluster_arn, tasks=task_arns)["tasks"]:
                table.append([get_field(task, f) for f in args.columns])
    page_output(format_table(table, column_names=args.columns, max_col_width=args.max_col_width))

parser = register_parser(tasks, help='List ECS tasks')
parser.add_argument("--desired-status", choices={'RUNNING', 'PENDING', 'STOPPED'}, default='RUNNING')
parser.add_argument("--columns", nargs="+")

def taskdefs(args):
    ecs = boto3.client('ecs')
    table = []
    for taskdef_arn in ecs.list_task_definitions()['taskDefinitionArns']:
        taskdef = ecs.describe_task_definition(taskDefinition=taskdef_arn)["taskDefinition"]
        table.append([get_field(taskdef, f) for f in args.columns])
    page_output(format_table(table, column_names=args.columns, max_col_width=args.max_col_width))

parser = register_parser(taskdefs, help='List ECS task definitions')
parser.add_argument("--columns", nargs="+", default=["family", "revision", "containerDefinitions"])

def sirs(args):
    page_output(tabulate(boto3.client('ec2').describe_spot_instance_requests()['SpotInstanceRequests'], args))

parser = register_parser(sirs, help='List EC2 spot instance requests')
parser.add_argument("--columns", nargs="+")

def sfrs(args):
    page_output(tabulate(boto3.client('ec2').describe_spot_fleet_requests()['SpotFleetRequestConfigs'], args))

parser = register_parser(sfrs, help='List EC2 spot fleet requests')
parser.add_argument("--columns", nargs="+")
parser.add_argument("--trim-col-names", nargs="+", default=["SpotFleetRequestConfig.", "SpotFleetRequest"])
parser.add_argument("--sort-by")

def key_pairs(args):
    page_output(tabulate(boto3.resource("ec2").key_pairs.all(), args))

parser = register_parser(key_pairs, help='List EC2 SSH key pairs')
parser.add_argument("--columns", nargs="+", default=["name", "key_fingerprint"])

def subnets(args):
    page_output(filter_and_tabulate(boto3.resource("ec2").subnets, args))

parser = register_listing_parser(subnets, help='List EC2 VPCs and subnets')
parser.add_argument("--columns", nargs="+")

def tables(args):
    page_output(tabulate(boto3.resource("dynamodb").tables.all(), args))

parser = register_parser(tables, help='List DynamoDB tables')
parser.add_argument("--columns", nargs="+")

def filesystems(args):
    efs = boto3.client("efs")
    table = []
    for filesystem in efs.describe_file_systems()["FileSystems"]:
        filesystem["tags"] = efs.describe_tags(FileSystemId=filesystem["FileSystemId"])["Tags"]
        for mount_target in efs.describe_mount_targets(FileSystemId=filesystem["FileSystemId"])["MountTargets"]:
            mount_target.update(filesystem)
            table.append(mount_target)
    args.columns += args.mount_target_columns
    page_output(tabulate(table, args, cell_transforms={"SizeInBytes": lambda x: x.get("Value") if x else None}))

parser = register_parser(filesystems, help='List EFS filesystems')
parser.add_argument("--columns", nargs="+")
parser.add_argument("--mount-target-columns", nargs="+")
