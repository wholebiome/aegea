"""
Manage AWS Batch jobs, queues, and compute environments.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse

from botocore.exceptions import ClientError

from .ls import register_parser, register_listing_parser
from .util import Timestamp, paginate, hashabledict
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.exceptions import AegeaException
from .util.compat import lru_cache
from .util.aws import ARN, resources, clients, expect_error_codes, ensure_iam_role, make_waiter

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
    return clients.batch.create_job_queue(jobQueueName=args.name,
                                          priority=args.priority,
                                          computeEnvironmentOrder=ces)

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
    return clients.batch.create_compute_environment(computeEnvironmentName=args.name,
                                                    type=args.type,
                                                    serviceRole=str(batch_iam_role))

parser = register_parser(create_compute_environment, parent=batch_parser, help="Create a Batch compute environment")
parser.add_argument("name")
parser.add_argument("--type", required=True, choices={"MANAGED", "UNMANAGED"})

def delete_compute_environment(args):
    clients.batch.update_compute_environment(computeEnvironment=args.name, state="DISABLED")
    wtr = make_waiter(clients.batch.describe_compute_environments, "computeEnvironments[].status", "VALID", "pathAny")
    wtr.wait(computeEnvironments=[args.name])
    clients.batch.delete_compute_environment(computeEnvironment=args.name)

parser = register_parser(delete_compute_environment, parent=batch_parser, help="Delete a Batch compute environment")
parser.add_argument("name")

def submit(args):
    raise NotImplementedError()

parser = register_parser(submit, parent=batch_parser, help="Submit a job to a Batch queue")

def terminate(args):
    raise NotImplementedError()

parser = register_parser(terminate, parent=batch_parser, help="Terminate a Batch job")
