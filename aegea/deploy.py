"""
Manage deployments from a GitHub repository.

Aegea deploy is a deployment manager daemon. It uses an SNS-SQS bus
to notify instances about updates to a GitHub repo. When
an update is detected, the deploy daemon pulls a new copy of the repo,
builds it, swaps it with the existing copy, and restarts your service.

To set up your AWS account for aegea deploy to track a particular
repo, run ``aegea deploy configure <repo URL>``. This will create an
SNS queue for notifications about the repo, an IAM user dedicated to
writing messages to this queue, and a GitHub post-commit hook to send
messages to the queue using the user's IAM credentials.

To set up instances to track deployments, create a systemd service
symlink like so:

    cd /etc/systemd/system/multi-user.target.wants
    ln -s /lib/systemd/system/aegea-deploy@.service aegea-deploy@<owner>-<repo>-<branch>.service

Replace <owner>, <repo>, and <branch> with your GitHub user or org name,
repo name, and branch to deploy from.

Any updates to the branch will trigger a rebuild of the repo. By
default, the build location is /opt/<owner>/<repo>. Each update is
pulled and built in a separate timestamped subdirectory by running
``make`` in the repo root, and symlinked upon success. Once the update
is successfully built, the daemon will run ``make reload`` in the repo
root to reload any services the app needs to run.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, getpass
from datetime import datetime

from botocore.exceptions import ClientError

from . import register_parser, logger
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

    iam_user_name = __name__ + "-github-event-relay"
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
