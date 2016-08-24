from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys
from datetime import datetime

from . import register_parser
from .util import Timestamp, paginate
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.aws import ARN, resolve_instance_id, resources, clients

def register_listing_parser(function, **kwargs):
    col_def = dict(default=kwargs.pop("column_defaults")) if "column_defaults" in kwargs else {}
    parser = register_parser(function, **kwargs)
    parser.add_argument("-c", "--columns", nargs="+", help="Names of columns to print", **col_def)
    return parser

def register_filtering_parser(function, **kwargs):
    parser = register_listing_parser(function, **kwargs)
    parser.add_argument("-f", "--filter", nargs="+", default=[],
                        help="Filter(s) to apply to output, e.g. --filter state=available")
    parser.add_argument("-t", "--tag", nargs="+", default=[], help="Tag(s) to filter output by, e.g. --tag Owner=bezos")
    return parser

def filter_collection(collection, args):
    filters = []
    # TODO: shlex?
    for f in getattr(args, "filter", []):
        name, value = f.split("=", 1)
        if collection.__class__.__name__ == "ec2.instancesCollectionManager":
            name = name.replace("_", "-")
            if name == "state":
                name = "instance-state-name"
        filters.append(dict(Name=name, Values=[value]))
    for t in getattr(args, "tag", []):
        name, value = t.split("=", 1)
        filters.append(dict(Name="tag:" + name, Values=[value]))
    return collection.filter(Filters=filters)

def filter_and_tabulate(collection, args, **kwargs):
    return tabulate(filter_collection(collection, args), args, **kwargs)

def ls(args):
    for col in "tags", "launch_time":
        if col not in args.columns:
            args.columns.append(col)
    def add_name(instance):
        instance.name = instance.id
        for tag in instance.tags or []:
            if tag["Key"] == "Name":
                instance.name = tag["Value"]
        return instance
    instances = [add_name(i) for i in filter_collection(resources.ec2.instances, args)]
    args.columns = ["name"] + args.columns
    cell_transforms = {
        "state": lambda x, r: x["Name"],
        "security_groups": lambda x, r: ", ".join(sg["GroupName"] for sg in x),
        "iam_instance_profile": lambda x, r: x.get("Arn", "").split("/")[-1] if x else None
    }
    page_output(tabulate(instances, args, cell_transforms=cell_transforms))

parser = register_filtering_parser(ls, help='List EC2 instances')
parser.add_argument("--sort-by")

def get_policies_for_principal(cell, row):
    return ", ".join([p.policy_name for p in row.policies.all()] + [p.policy_name for p in row.attached_policies.all()])

def users(args):
    current_user = resources.iam.CurrentUser()
    def mark_cur_user(cell, row):
        return ">>>" if row.user_id == current_user.user_id else ""
    users = list(resources.iam.users.all())
    for user in users:
        user.cur = ""
    cell_transforms = {"cur": mark_cur_user, "policies": get_policies_for_principal}
    page_output(tabulate(users, args, cell_transforms=cell_transforms))

parser = register_listing_parser(users, help='List IAM users')

def groups(args):
    page_output(tabulate(resources.iam.groups.all(), args, cell_transforms={"policies": get_policies_for_principal}))

parser = register_listing_parser(groups, help='List IAM groups')

def roles(args):
    page_output(tabulate(resources.iam.roles.all(), args, cell_transforms={"policies": get_policies_for_principal}))

parser = register_listing_parser(roles, help='List IAM roles')

def policies(args):
    page_output(tabulate(resources.iam.policies.all(), args))

parser = register_listing_parser(policies, help='List IAM policies')
parser.add_argument("--sort-by")

def volumes(args):
    table = [[get_cell(i, f) for f in args.columns] for i in filter_collection(resources.ec2.volumes, args)]
    if "attachments" in args.columns:
        for row in table:
            att_col_idx = args.columns.index("attachments")
            row[att_col_idx] = ", ".join(a["InstanceId"] for a in row[att_col_idx])
    page_output(format_table(table, column_names=args.columns, max_col_width=args.max_col_width))

parser = register_filtering_parser(volumes, help='List EC2 EBS volumes')

def snapshots(args):
    account_id = ARN(resources.iam.CurrentUser().arn).account_id
    page_output(filter_and_tabulate(resources.ec2.snapshots.filter(OwnerIds=[account_id]), args))

parser = register_filtering_parser(snapshots, help='List EC2 EBS snapshots')

def buckets(args):
    """
    List S3 buckets. See also "aws s3 ls". Use "aws s3 ls NAME" to list bucket contents.
    """
    page_output(filter_and_tabulate(resources.s3.buckets, args))

parser = register_filtering_parser(buckets)

def console(args):
    instance_id = resolve_instance_id(args.instance)
    err = '[No console output received for {}. Console output may lag by several minutes.]'.format(instance_id)
    page_output(resources.ec2.Instance(instance_id).console_output().get('Output', err))

parser = register_parser(console, help='Get console output for an EC2 instance')
parser.add_argument("instance")

def zones(args):
    table = []
    rrs_cols = ["Name", "Type", "TTL"]
    record_cols = ["Value"]
    for zone in paginate(clients.route53.get_paginator('list_hosted_zones')):
        if args.zones and zone["Name"] not in args.zones + [z + "." for z in args.zones]:
            continue
        for rrs in paginate(clients.route53.get_paginator('list_resource_record_sets'), HostedZoneId=zone["Id"]):
            for record in rrs.get("ResourceRecords", [rrs.get("AliasTarget", {})]):
                row = [rrs.get(f) for f in rrs_cols]
                row += [record.get(f, record.get("DNSName")) for f in record_cols]
                row += [get_field(zone, "Config.PrivateZone"), zone["Id"].rpartition("/")[-1]]
                table.append(row)
    column_names = rrs_cols + record_cols + ["Private", "Id"]
    page_output(format_table(table, column_names=column_names, max_col_width=args.max_col_width))

parser = register_parser(zones, help='List Route53 DNS zones')
parser.add_argument("zones", nargs='*')

def images(args):
    page_output(filter_and_tabulate(resources.ec2.images.filter(Owners=["self"]), args))

parser = register_filtering_parser(images, help='List EC2 AMIs')
parser.add_argument("--sort-by")

def security_groups(args):
    page_output(filter_and_tabulate(resources.ec2.security_groups, args))

parser = register_filtering_parser(security_groups, help='List EC2 security groups')

def logs(args):
    if args.log_group and args.log_stream:
        args.pattern, args.start_time, args.end_time = None, None, None
        return grep(args)
    table = []
    group_cols = ["logGroupName"]
    stream_cols = ["logStreamName", "lastIngestionTime", "storedBytes"]
    args.columns = group_cols + stream_cols
    for group in paginate(clients.logs.get_paginator('describe_log_groups')):
        if args.log_group and group["logGroupName"] != args.log_group:
            continue
        n = 0
        for stream in paginate(clients.logs.get_paginator('describe_log_streams'),
                               logGroupName=group["logGroupName"], orderBy="LastEventTime", descending=True):
            now = datetime.utcnow().replace(microsecond=0)
            stream["lastIngestionTime"] = now - datetime.utcfromtimestamp(stream.get("lastIngestionTime", 0)//1000)
            table.append(dict(group, **stream))
            n += 1
            if n >= args.max_streams_per_group:
                break
    page_output(tabulate(table, args))

parser = register_parser(logs, help='List CloudWatch Logs groups and streams')
parser.add_argument("--max-streams-per-group", "-n", type=int, default=8)
parser.add_argument("--sort-by", default="lastIngestionTime:reverse")
parser.add_argument("log_group", nargs="?", help="CloudWatch log group")
parser.add_argument("log_stream", nargs="?", help="CloudWatch log stream")

def grep(args):
    filter_args = dict(logGroupName=args.log_group)
    if args.log_stream:
        filter_args.update(logStreamNames=[args.log_stream])
    if args.pattern:
        filter_args.update(filterPattern=args.pattern)
    if args.start_time:
        filter_args.update(startTime=int(args.start_time.timestamp() * 1000))
    if args.end_time:
        filter_args.update(endTime=int(args.end_time.timestamp() * 1000))
    num_results = 0
    for event in paginate(clients.logs.get_paginator('filter_log_events'), **filter_args):
        if "timestamp" not in event or "message" not in event:
            continue
        print(str(Timestamp(event["timestamp"])), event["message"])
        num_results += 1
    return SystemExit(os.EX_OK if num_results > 0 else os.EX_DATAERR)

parser = register_parser(grep, help='Filter and print events in a CloudWatch Logs stream or group of streams')
parser.add_argument("pattern", help="""CloudWatch filter pattern to use. Case-sensitive. See
http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/FilterAndPatternSyntax.html""")
parser.add_argument("log_group", help="CloudWatch log group")
parser.add_argument("log_stream", nargs="?", help="CloudWatch log stream")
parser.add_argument("--start-time", type=Timestamp, default=Timestamp("-7d"),
                    help=Timestamp.__doc__, metavar="-7d")
parser.add_argument("--end-time", type=Timestamp, help=Timestamp.__doc__)

def clusters(args):
    cluster_arns = sum([p["clusterArns"] for p in clients.ecs.get_paginator('list_clusters').paginate()], [])
    page_output(tabulate(clients.ecs.describe_clusters(clusters=cluster_arns)["clusters"], args))

parser = register_listing_parser(clusters, help='List ECS clusters')

def tasks(args):
    cluster_arns = sum([p["clusterArns"] for p in clients.ecs.get_paginator('list_clusters').paginate()], [])
    table = []
    for cluster_arn in cluster_arns:
        list_tasks_args = dict(cluster=cluster_arn, desiredStatus=args.desired_status)
        paginator = clients.ecs.get_paginator('list_tasks')
        task_arns = sum([p["taskArns"] for p in paginator.paginate(**list_tasks_args)], [])
        if task_arns:
            for task in clients.ecs.describe_tasks(cluster=cluster_arn, tasks=task_arns)["tasks"]:
                table.append(task)
    page_output(tabulate(table, args))

parser = register_listing_parser(tasks, help='List ECS tasks')
parser.add_argument("--desired-status", choices={'RUNNING', 'PENDING', 'STOPPED'}, default='RUNNING')

def taskdefs(args):
    table = []
    for taskdef_arn in clients.ecs.list_task_definitions()['taskDefinitionArns']:
        table.append(clients.ecs.describe_task_definition(taskDefinition=taskdef_arn)["taskDefinition"])
    page_output(tabulate(table, args))

parser = register_listing_parser(taskdefs, help='List ECS task definitions',
                                 column_defaults=["family", "revision", "containerDefinitions"])

def sirs(args):
    page_output(tabulate(clients.ec2.describe_spot_instance_requests()['SpotInstanceRequests'], args))

parser = register_listing_parser(sirs, help='List EC2 spot instance requests')

def sfrs(args):
    page_output(tabulate(paginate(clients.ec2.get_paginator('describe_spot_fleet_requests')), args))

parser = register_listing_parser(sfrs, help='List EC2 spot fleet requests')
parser.add_argument("--trim-col-names", nargs="+", default=["SpotFleetRequestConfig.", "SpotFleetRequest"])
parser.add_argument("--sort-by")

def key_pairs(args):
    page_output(tabulate(resources.ec2.key_pairs.all(), args))

parser = register_listing_parser(key_pairs, help='List EC2 SSH key pairs', column_defaults=["name", "key_fingerprint"])

def subnets(args):
    page_output(filter_and_tabulate(resources.ec2.subnets, args))

parser = register_filtering_parser(subnets, help='List EC2 VPCs and subnets')

def tables(args):
    page_output(tabulate(resources.dynamodb.tables.all(), args))

parser = register_listing_parser(tables, help='List DynamoDB tables')

def subscriptions(args):
    page_output(tabulate(paginate(clients.sns.get_paginator('list_subscriptions')), args))

parser = register_listing_parser(subscriptions, help='List SNS subscriptions',
                                 column_defaults=['SubscriptionArn', 'Protocol', 'Endpoint'])

def filesystems(args):
    table = []
    for filesystem in clients.efs.describe_file_systems()["FileSystems"]:
        filesystem["tags"] = clients.efs.describe_tags(FileSystemId=filesystem["FileSystemId"])["Tags"]
        for mount_target in clients.efs.describe_mount_targets(FileSystemId=filesystem["FileSystemId"])["MountTargets"]:
            mount_target.update(filesystem)
            table.append(mount_target)
    args.columns += args.mount_target_columns
    page_output(tabulate(table, args, cell_transforms={"SizeInBytes": lambda x, r: x.get("Value") if x else None}))

parser = register_listing_parser(filesystems, help='List EFS filesystems')
parser.add_argument("--mount-target-columns", nargs="+")

def limits(args):
    """
    Describe limits in effect on your AWS account. See also https://console.aws.amazon.com/ec2/v2/home#Limits:
    """
    # https://aws.amazon.com/about-aws/whats-new/2014/06/19/amazon-ec2-service-limits-report-now-available/
    # Console-only APIs: getInstanceLimits, getAccountLimits, getAutoscalingLimits, getHostLimits
    # http://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#DynamoDB.Client.describe_limits
    attrs = ["max-instances", "vpc-max-security-groups-per-interface", "vpc-max-elastic-ips"]
    table = clients.ec2.describe_account_attributes(AttributeNames=attrs)["AccountAttributes"]
    page_output(tabulate(table, args))

parser = register_parser(limits)

def cmks(args):
    aliases = {alias.get("TargetKeyId"): alias for alias in paginate(clients.kms.get_paginator('list_aliases'))}
    table = []
    for key in paginate(clients.kms.get_paginator('list_keys')):
        key.update(aliases.get(key["KeyId"], {}))
        table.append(key)
    page_output(tabulate(table, args))

parser = register_parser(cmks, help="List KMS Customer Master Keys")

def certificates(args):
    page_output(tabulate(paginate(clients.acm.get_paginator('list_certificates')), args))

parser = register_parser(certificates, help="List Amazon Certificate Manager SSL certificates")
