"""
Manage AWS Batch jobs, queues, and compute environments.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, base64

from botocore.exceptions import ClientError

from . import logger
from .ls import register_parser, register_listing_parser, grep, grep_parser
from .util import Timestamp, paginate, hashabledict
from .util.printing import format_table, page_output, get_field, get_cell, tabulate, YELLOW, RED, GREEN, BOLD, ENDC
from .util.exceptions import AegeaException
from .util.crypto import ensure_ssh_key
from .util.compat import lru_cache
from .util.aws import (ARN, resources, clients, expect_error_codes, ensure_instance_profile, make_waiter, ensure_subnet,
                       ensure_vpc, ensure_security_group, SpotFleetBuilder)

def batch(args):
    batch_parser.print_help()

batch_parser = register_parser(batch, help="Manage AWS Batch resources", description=__doc__,
                               formatter_class=argparse.RawTextHelpFormatter)

def queues(args):
    table = clients.batch.describe_job_queues()["jobQueues"]
    page_output(tabulate(table, args))

parser = register_listing_parser(queues, parent=batch_parser, help="List Batch queues")

def create_queue(args):
    ces = [dict(computeEnvironment=e, order=i) for i, e in enumerate(args.compute_environments)]
    queue = clients.batch.create_job_queue(jobQueueName=args.name, priority=args.priority, computeEnvironmentOrder=ces)
    make_waiter(clients.batch.describe_job_queues, "jobQueues[].status", "VALID", "pathAny").wait(jobQueues=[args.name])
    return queue

parser = register_parser(create_queue, parent=batch_parser, help="Create a Batch queue")
parser.add_argument("name")
parser.add_argument("--priority", type=int, default=5)
parser.add_argument("--compute-environments", nargs="+", required=True)

def delete_queue(args):
    clients.batch.update_job_queue(jobQueue=args.name, state="DISABLED")
    make_waiter(clients.batch.describe_job_queues, "jobQueues[].status", "VALID", "pathAny").wait(jobQueues=[args.name])
    clients.batch.delete_job_queue(jobQueue=args.name)

parser = register_parser(delete_queue, parent=batch_parser, help="Delete a Batch queue")
parser.add_argument("name")

def compute_environments(args):
    table = clients.batch.describe_compute_environments()["computeEnvironments"]
    page_output(tabulate(table, args))

parser = register_listing_parser(compute_environments, parent=batch_parser, help="List Batch compute environments")

def create_compute_environment(args):
    batch_iam_role = ARN(service="iam", region="", resource="role/service-role/AWSBatchServiceRole")
    vpc = ensure_vpc()
    ensure_ssh_key(args.ssh_key_name)
    instance_profile = ensure_instance_profile(args.instance_role,
                                               policies={"service-role/AmazonAPIGatewayPushToCloudWatchLogs",
                                                         "service-role/AmazonEC2ContainerServiceforEC2Role"})
    compute_resources = dict(type=args.compute_type,
                             minvCpus=args.min_vcpus, desiredvCpus=args.desired_vcpus, maxvCpus=args.max_vcpus,
                             instanceTypes=["optimal"],
                             subnets=[subnet.id for subnet in vpc.subnets.all()],
                             securityGroupIds=[ensure_security_group("aegea.launch", vpc).id],
                             instanceRole=instance_profile.name,
                             bidPercentage=100,
                             spotIamFleetRole=SpotFleetBuilder.get_iam_fleet_role().name,
                             ec2KeyPair=args.ssh_key_name)
    logger.info("Creating compute environment in %s", vpc)
    compute_environment = clients.batch.create_compute_environment(computeEnvironmentName=args.name,
                                                                   type=args.type,
                                                                   computeResources=compute_resources,
                                                                   serviceRole=str(batch_iam_role))
    wtr = make_waiter(clients.batch.describe_compute_environments, "computeEnvironments[].status", "VALID", "pathAny",
                      delay=2, max_attempts=300)
    wtr.wait(computeEnvironments=[args.name])
    return compute_environment

cce_parser = register_parser(create_compute_environment, parent=batch_parser, help="Create a Batch compute environment")
cce_parser.add_argument("name")
cce_parser.add_argument("--type", choices={"MANAGED", "UNMANAGED"}, default="MANAGED")
cce_parser.add_argument("--compute-type", choices={"EC2", "SPOT"}, default="SPOT")
cce_parser.add_argument("--min-vcpus", type=int, default=0)
cce_parser.add_argument("--desired-vcpus", type=int, default=2)
cce_parser.add_argument("--max-vcpus", type=int, default=8)
cce_parser.add_argument("--ssh-key-name", default=__name__)
cce_parser.add_argument("--instance-role", default=__name__)

def delete_compute_environment(args):
    clients.batch.update_compute_environment(computeEnvironment=args.name, state="DISABLED")
    wtr = make_waiter(clients.batch.describe_compute_environments, "computeEnvironments[].status", "VALID", "pathAny")
    wtr.wait(computeEnvironments=[args.name])
    clients.batch.delete_compute_environment(computeEnvironment=args.name)

parser = register_parser(delete_compute_environment, parent=batch_parser, help="Delete a Batch compute environment")
parser.add_argument("name")

def ensure_job_definition(args):
    container_props = {k: vars(args)[k] for k in ("image", "vcpus", "memory", "privileged", "environment")}
    if args.volumes:
        container_props.update(volumes=[], mountPoints=[])
        for i, (host_path, guest_path) in enumerate(args.volumes):
            container_props["volumes"].append({"host": {"sourcePath": host_path}, "name": "vol%d" % i})
            container_props["mountPoints"].append({"sourceVolume": "vol%d" % i, "containerPath": guest_path})
    shellcode = ['set -a', 'source /etc/environment',
                 'if [ -f /etc/default/locale ]; then source /etc/default/locale; fi',
                 'set +a', 'set -eo pipefail', 'source /etc/profile']
    if args.execute:
        args.command = []
        payload = base64.b64encode(args.execute.read()).decode()
        shellcode += ['BATCH_SCRIPT=$(mktemp --tmpdir "$AWS_BATCH_CE_NAME.$AWS_BATCH_JQ_NAME.$AWS_BATCH_JOB_ID.XXXXX")',
                      'echo "{}" | base64 --decode > "$BATCH_SCRIPT"'.format(payload),
                      'chmod +x "$BATCH_SCRIPT"',
                      '"$BATCH_SCRIPT"']
    else:
        shellcode += ['for cmd in "$@"; do /bin/bash -c "$cmd"; done']
    container_props["command"] = ["/bin/bash", "-c", ";".join(shellcode), __name__] + args.command
    return clients.batch.register_job_definition(jobDefinitionName=__name__.replace(".", "_"),
                                                 type="container",
                                                 containerProperties=container_props)

def ensure_queue(name):
    cq_args = argparse.Namespace(name=name, priority=5, compute_environments=[name])
    try:
        return create_queue(cq_args)
    except ClientError:
        create_compute_environment(cce_parser.parse_args(args=[name]))
        return create_queue(cq_args)

def submit(args):
    if args.job_definition_arn is None:
        args.job_definition_arn = ensure_job_definition(args)["jobDefinitionArn"]
    submit_args = dict(jobName=args.name,
                       jobQueue=args.queue,
                       dependsOn=args.depends_on,
                       jobDefinition=args.job_definition_arn,
                       parameters=args.parameters,
                       containerOverrides={})
    try:
        job = clients.batch.submit_job(**submit_args)
    except ClientError:
        # FIXME: only catch "no queue" error
        ensure_queue(args.queue)
        job = clients.batch.submit_job(**submit_args)
    if args.watch:
        watch(watch_parser.parse_args([job["jobId"]]))
    elif args.wait:
        raise NotImplementedError()
    return job

parser = register_parser(submit, parent=batch_parser, help="Submit a job to a Batch queue")
parser.add_argument("--name", default=__name__.replace(".", "_"))
parser.add_argument("--queue", default=__name__.replace(".", "_"))
parser.add_argument("--depends-on", nargs="+", default=[])
parser.add_argument("--job-definition-arn")
group = parser.add_mutually_exclusive_group()
group.add_argument("--watch", action="store_true", help="Monitor submitted job, stream log until job completes")
group.add_argument("--wait", action="store_true", help="Block on job. Exit with code 0 if job succeeded, 1 if failed")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--command", nargs="+", help="Run these commands as the job (using " + BOLD("bash -c") + ")")
group.add_argument("--execute", type=argparse.FileType("rb"), metavar="EXECUTABLE",
                   help="Read this executable file and run it as the job",)
group = parser.add_argument_group(title="job definition parameters", description="""
See http://docs.aws.amazon.com/batch/latest/userguide/job_definition_parameters.html""")
group.add_argument("--image", default="ubuntu", help="Docker image URL to use for running Batch job")
group.add_argument("--vcpus", type=int, default=1)
group.add_argument("--memory", type=int, default=1024)
group.add_argument("--privileged", action="store_true", default=False)
group.add_argument("--volumes", nargs="+", metavar="HOST_PATH=GUEST_PATH", type=lambda x: x.split("=", 1), default=[])
group.add_argument("--environment", nargs="+", metavar="NAME=VALUE",
                   type=lambda x: dict(zip(["name", "value"], x.split("=", 1))), default=[])
group.add_argument("--parameters", nargs="+", metavar="NAME=VALUE", type=lambda x: x.split("=", 1), default={})

def terminate(args):
    return clients.batch.terminate_job(jobId=args.job_id, reason="Terminated by {}".format(__name__))

parser = register_parser(terminate, parent=batch_parser, help="Terminate a Batch job")
parser.add_argument("job_id")

def ls(args, page_size=100):
    table, job_ids = [], []
    for q in args.queues or [q["jobQueueName"] for q in clients.batch.describe_job_queues()["jobQueues"]]:
        for s in args.status:
            job_ids.extend(j["jobId"] for j in clients.batch.list_jobs(jobQueue=q, jobStatus=s)["jobSummaryList"])
    for i in range(0, len(job_ids), page_size):
        table.extend(clients.batch.describe_jobs(jobs=job_ids[i:i+page_size])["jobs"])
    page_output(tabulate(table, args, cell_transforms={"createdAt": lambda cell, row: Timestamp(cell)}))

parser = register_listing_parser(ls, parent=batch_parser, help="List Batch jobs")
parser.add_argument("--queues", nargs="+")
parser.add_argument("--status", nargs="+",
                    default="SUBMITTED PENDING RUNNABLE STARTING RUNNING SUCCEEDED FAILED".split())

def format_job_status(status):
    colors = dict(SUBMITTED=YELLOW(), PENDING=YELLOW(), RUNNABLE=BOLD()+YELLOW(),
                  STARTING=GREEN(), RUNNING=GREEN(),
                  SUCCEEDED=BOLD()+GREEN(), FAILED=BOLD()+RED())
    return colors[status] + status + ENDC()

def get_logs(args):
    log_stream_args = dict(logGroupName="/aws/batch/job",
                           logStreamNamePrefix="{}/{}".format(args.job_name, args.job_id))
    for log_stream in paginate(clients.logs.get_paginator("describe_log_streams"), **log_stream_args):
        filter_args = dict(logGroupName="/aws/batch/job", logStreamNames=[log_stream["logStreamName"]],
                           startTime=getattr(args, "start_time", 0))
        for event in paginate(clients.logs.get_paginator("filter_log_events"), **filter_args):
            if "timestamp" in event and "message" in event:
                print(str(Timestamp(event["timestamp"])), event["message"])
                args.start_time = event["timestamp"]

get_logs_parser = register_parser(get_logs, parent=batch_parser, help="Retrieve logs for a Batch job")
get_logs_parser.add_argument("job_id")
get_logs_parser.add_argument("job_name", nargs="?", default=__name__.replace(".", "_"))
get_logs_parser.add_argument("--start-time", type=int, help=argparse.SUPPRESS)

def watch(args):
    args.job_name = clients.batch.describe_jobs(jobs=[args.job_id])["jobs"][0]["jobName"]
    logger.info("Watching job %s (%s)", args.job_id, args.job_name)
    last_status = None
    while last_status not in {"SUCCEEDED", "FAILED"}:
        job_desc = clients.batch.describe_jobs(jobs=[args.job_id])["jobs"][0]
        if job_desc["status"] != last_status:
            logger.info("Job %s %s", args.job_id, format_job_status(job_desc["status"]))
            last_status = job_desc["status"]
        if job_desc["status"] in {"RUNNING", "SUCCEEDED", "FAILED"}:
            get_logs(args)
        if "reason" in job_desc.get("container", {}):
            logger.info("Job %s: %s", args.job_id, job_desc["container"]["reason"])

watch_parser = register_parser(watch, parent=batch_parser, help="Monitor a running Batch job and stream its logs")
watch_parser.add_argument("job_id")
