"""
Manage deployments from a GitHub repository.

Aegea deploy is a deployment manager daemon. It uses an SNS-SQS bus
to notify instances about updates to a GitHub repo. When
an update is detected, the deploy daemon pulls a new copy of the repo,
builds it, swaps it with the existing copy, and restarts your service.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, getpass
from datetime import datetime

from botocore.exceptions import ClientError

from . import register_parser, logger
from .util import Timestamp, paginate
from .util.printing import format_table, page_output, get_field, get_cell, tabulate, BOLD
from .util.aws import ARN, resources, clients, IAMPolicyBuilder

def deploy(args):
    deploy_parser.print_help()

deploy_parser = register_parser(deploy, help='Manage deployments of GitHub repositories', description=__doc__,
                                formatter_class=argparse.RawTextHelpFormatter)

def configure(args):
    import github3
    try:
        gh = github3.login(token=os.environ["GH_AUTH"])
    except Exception:
        msg = "GitHub login failed. Please get a token at https://github.com/settings/tokens and set the GH_AUTH environment variable to its value." # noqa
        return SystemExit(msg)
    if args.repo.endswith(".git"):
        args.repo = args.repo[:len(".git")]
    gh_owner_name, gh_repo_name = args.repo.split("/")[-2:]
    repo = gh.repository(gh_owner_name, gh_repo_name)

    iam_user_name = "{}-github-event-relay".format(__name__)
    try:
        user = resources.iam.User(iam_user_name)
        user.load()
    except ClientError:
        user = resources.iam.create_user(UserName=iam_user_name)

    topic = resources.sns.create_topic(Name="github-{}-{}-events".format(gh_owner_name, gh_repo_name))
    policy = IAMPolicyBuilder(action="sns:Publish", resource=topic.arn)
    user.create_policy(PolicyName="sqs_send_message", PolicyDocument=str(policy))

    for key in user.access_keys.all():
        key.delete()
    key = user.create_access_key_pair()
    repo.create_hook("amazonsns", dict(sns_topic=topic.arn,
                                       sns_region=ARN(topic.arn).region,
                                       aws_key=key.id,
                                       aws_secret=key.secret))
    logger.info("Created SNS topic %s and GitHub hook for repo %s", topic, repo)
    return dict(topic_arn=topic.arn)

parser = register_parser(configure, parent=deploy_parser)
parser.add_argument('repo')

def status(args):
    table = []
    queues = list(resources.sqs.queues.filter(QueueNamePrefix="github"))
    for topic in resources.sns.topics.all():
        if ARN(topic.arn).resource.startswith("github"):
            for queue in queues:
                if ARN(queue.attributes["QueueArn"]).resource.startswith(ARN(topic.arn).resource):
                    table.append(dict(Topic=topic, Queue=queue))
    args.columns = ["Topic", "Queue"]
    page_output(tabulate(table, args))

parser = register_parser(status, parent=deploy_parser)
