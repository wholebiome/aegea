"""
Manage secrets (credentials) using an S3 bucket.

Secrets are credentials (private SSH keys, API keys, passwords, etc.)  for use
by services that run in your AWS account. This utility does not manage AWS
credentials, since the AWS IAM API provides a way to do so through IAM roles,
instance profiles, and instance metadata. Instead, instance role credentials are
used as primary credentials to access any other credentials needed by your
services.

When you run ``aegea secrets`` with AWS admin credentials, it creates an S3
bucket with the name ``credentials-<ACCOUNT-ID>``, where <ACCOUNT-ID> is the
numeric ID of your AWS account. It then sets access policies on the bucket and
on your IAM users, groups, and roles to ensure that they have read-only access
only to paths within that bucket. For example, an IAM user ``alice`` will only
have read access to ``credentials-123456789012/user/alice``. All users in the
group ``devs`` have access to ``credentials-123456789012/group/devs``, and all
instances with the role ``lims`` can access
``credentials-123456789012/role/lims``. Conversely, without admin access, these
principals can't read each other's directories.

Upload and manage credentials with ``aegea secrets``. On an EC2 instance, read
credentials with ``aegea-get-secret``. Once you retrieve a secret with
``aegea-get-secret``, try to avoid saving it on the filesystem or passing it in
process arguments. Instead, try passing it as an environment variable value or
on process standard input.

For more information about credential storage best practices, see
http://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html
and https://www.vaultproject.io/.

Examples:

    aegea secrets put deploy.foo.bar --generate-ssh-key --iam-roles aegea.launch > deploy.foo.bar.pub

    RAILGUN_PASSWORD=passw0rd aegea secrets put RAILGUN_PASSWORD --iam-groups space_marines

    eval $(ssh-agent -s)
    aegea-get-secret deploy.bitbucket.my-private-repo | ssh-add /dev/stdin
    git clone git@bitbucket.org:my-org/my-private-repo.git

"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, subprocess, json, copy
from textwrap import fill
import boto3

from . import register_parser
from .util.aws import ARN
from .util.printing import format_table, page_output, tabulate
from .util.exceptions import AegeaException
from .util.crypto import new_ssh_key, hostkey_line
from .util.compat import StringIO

class IAMPolicyBuilder:
    def __init__(self, **kwargs):
        self.policy = dict(Version="2012-10-17", Statement=[])
        self.add_statement(**kwargs)

    def add_statement(self, principal=None, action=None, effect="Allow", resource=None):
        statement = dict(Action=[], Effect=effect, Resource=[])
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
        self.policy["Statement"][-1]["Resource"].append(resource)

def build_s3_bucket_policy(account_id, bucket):
    resource = "arn:aws:s3:::" + bucket + "/user/${aws:userid}/*"
    return IAMPolicyBuilder(principal={"AWS": account_id}, action="s3:GetObject", resource=resource).policy

def build_iam_policy(principal, bucket):
    resource = "arn:aws:s3:::{bucket}/{principal}/*".format(bucket=bucket, principal=principal)
    return IAMPolicyBuilder(action="s3:GetObject", resource=resource).policy

def secrets(args):
    iam = boto3.resource("iam")
    s3 = boto3.resource("s3")
    account_id = ARN(iam.CurrentUser().user.arn).account_id
    bucket_name = "credentials-{}".format(account_id)
    bucket = s3.Bucket(bucket_name)
    bucket.create()
    policy = bucket.Policy()
    policy.put(Policy=json.dumps(build_s3_bucket_policy(account_id, bucket.name)))
    for instance_profile in args.instance_profiles:
        for role in iam.InstanceProfile(instance_profile).roles:
            args.iam_roles.append(role.name)
    principals = []
    for role_name in args.iam_roles:
        principals.append(iam.Role(role_name))
    for group_name in args.iam_groups:
        principals.append(iam.Group(group_name))
    for principal in principals:
        policy_name = __name__ + "." + ARN(principal.arn).resource.replace("/", ".")
        for policy in iam.policies.all():
            if policy.policy_name == policy_name:
                break
        else:
            policy = iam.create_policy(PolicyName=policy_name,
                                       PolicyDocument=json.dumps(build_iam_policy(ARN(principal.arn).resource, bucket.name)))
        principal.attach_policy(PolicyArn=policy.arn)
    for user_name in args.iam_users:
        # Users are subject to the /user/${aws:userid} parametric bucket policy, so don't get policies attached to them
        principals.append(iam.User(user_name))
    if len(principals) == 0 and args.action != "ls":
        raise AegeaException('Please supply one or more principals with "--instance-profiles" or "--iam-{roles,users,groups}".')
    if len(args.secrets) == 0 and args.action != "ls":
        raise AegeaException('Please supply one or more secrets and pass their value(s) via environment variable or on stdin.')
    if args.action == "ls":
        page_output(tabulate(bucket.objects.all(), args, cell_transforms={"owner": lambda x: x.get("DisplayName") if x else None}))
    elif args.action == "put":
        for principal in principals:
            for secret_name in args.secrets:
                if args.generate_ssh_key:
                    ssh_key = new_ssh_key()
                    buf = StringIO()
                    ssh_key.write_private_key(buf)
                    secret_value = buf.getvalue()
                    print(hostkey_line(hostnames=[], key=ssh_key).strip())
                elif secret_name in os.environ:
                    secret_value = os.environ[secret_name]
                else:
                    secret_value = sys.stdin.read()
                bucket.Object(os.path.join(ARN(principal.arn).resource, secret_name)).put(Body=secret_value.encode(), ServerSideEncryption='AES256')
    elif args.action == "delete":
        for principal in principals:
            for secret_name in args.secrets:
                bucket.Object(os.path.join(ARN(principal.arn).resource, secret_name)).delete()

parser = register_parser(secrets, help='Manage credentials (secrets)', description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('action', choices=["ls", "put", "delete"])
parser.add_argument('secrets', nargs='*',
                    help=fill('List the secret names. For put, pass the secret value on stdin (and name only one secret), or pass multiple secret values via environment variables with the same name as the secret.'))
parser.add_argument('--instance-profiles', nargs='+', default=[])
parser.add_argument('--iam-roles', nargs='+', default=[])
parser.add_argument('--iam-groups', nargs='+', default=[])
parser.add_argument('--iam-users', nargs='+', default=[],
                    help=fill("Name(s) of IAM instance profiles, roles, groups, or users who will be granted access to the secret"))
parser.add_argument('--generate-ssh-key', action='store_true',
                    help=fill("Generate a new SSH key pair and write the private key as the secret value; write the public key to stdout"))
parser.add_argument("--columns", nargs="+",
                    default=["bucket_name", "key", "owner", "size", "last_modified", "storage_class"])
