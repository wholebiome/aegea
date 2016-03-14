"""Manage secrets (credentials) using an S3 bucket.

Secrets are credentials for use by services that run in your AWS account. This
utility does not manage AWS credentials, since the AWS IAM API provides a way to
do so through IAM roles, instance profiles, and instance metadata.

Upload and manage credentials with ``aegea secrets``. On an EC2
instance, read credentials with ``aegea-get-secret``.

When you run ``aegea secrets`` with AWS admin credentials, it creates
an S3 bucket with the name ``credentials-<ACCOUNT-ID>``, where
ACCOUNT-ID is the numeric ID of your AWS account. It then sets access
policies on the bucket and on your IAM users, groups, and roles to
ensure that they have read-only access only to paths within that
bucket. For example, an IAM user ``alice`` will only have read access
to ``credentials-123456789012/user/alice``. All users in the group
``devs`` have access to ``credentials-123456789012/group/devs``, and
all instances with the role ``lims`` can access
``credentials-123456789012/role/lims``. Conversely, without admin
access, these principals can't read each other's directories.

For more information about credential storage best practices, see
http://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html
and https://www.vaultproject.io/.

"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, subprocess, json, copy
import boto3

from . import register_parser
from .util.aws import ARN

'''
def build_policy_doc(bucket, prefix="/*", perms="r"):
    actions = []
    if "r" in perms:
        actions.extend(["s3:ListBucket", "s3:GetObject"])
    if "w" in perms:
        actions.extend(["s3:PutObject", "s3:DeleteObject"])
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": [str(ARN(service="s3", resource=bucket.name)),
                             str(ARN(service="s3", resource=bucket.name + prefix))]
            }
        ]
    }
    return json.dumps(doc)

def set_permissions(bucket):
    ssh_admin_group = get_group(name="ssh_admin")
    ssh_admin_group.create_policy(PolicyName="keymaker-ssh-admin",
                                  PolicyDocument=build_policy_doc(bucket, perms="rw"))
    ssh_admin_group.add_user(UserName=iam.CurrentUser().user_name)

    ssh_group = get_group()
    ssh_group.create_policy(PolicyName="keymaker-ssh-group",
                            PolicyDocument=build_policy_doc(bucket, perms="r"))
    for user in iam.users.all():
        ssh_group.add_user(UserName=user.name)
        user.create_policy(PolicyName="keymaker-ssh-user",
                           PolicyDocument=build_policy_doc(bucket, perms="w", prefix="/users/" + user.name))
'''

def build_s3_bucket_policy(account_id, bucket):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Principal": {"AWS": account_id},
                "Action": [
                    "s3:GetObject"
                ],
                "Effect": "Allow",
                "Resource": ["arn:aws:s3:::" + bucket + "/user/${aws:userid}/*"]
            }
        ]
    }

def build_iam_policy(principal, bucket):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                    "s3:GetObject"
                ],
                "Effect": "Allow",
                "Resource": ["arn:aws:s3:::{bucket}/{principal}/*".format(bucket=bucket, principal=principal)]
            }
        ]
    }

def qualified_name(principal):
    return ARN(principal.arn).resource

def secrets(args):
    iam = boto3.resource("iam")
    s3 = boto3.resource("s3")
    account_id = ARN(iam.CurrentUser().user.arn).account_id
    if args.bucket_name is None:
        args.bucket_name = "credentials-{}".format(account_id)
    bucket = s3.Bucket(args.bucket_name)
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
        principals.append(iam.User(user_name))
    if args.action == "list":
        for object_summary in bucket.objects.all():
            print(object_summary)
    elif args.action == "put":
        for principal in principals:
            for secret in args.secrets:
                secret_name, secret_value = secret.split("=", 1)
                bucket.Object(os.path.join(ARN(principal.arn).resource, secret_name)).put(Body=secret_value.encode(), ServerSideEncryption='AES256')
    elif args.action == "delete":
        for principal in principals:
            for secret_name in args.secrets:
                bucket.Object(os.path.join(ARN(principal.arn).resource, secret_name)).delete()

parser = register_parser(secrets, help='Manage credentials (secrets)', description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('action', choices=["list", "put", "delete"])
parser.add_argument('secrets', nargs='*', help='For put, list secrets as name=value assignments, e.g. "aegea secrets put password=foo". For delete, list just the secret names.')
parser.add_argument('--bucket-name')
parser.add_argument('--instance-profiles', nargs='+', default=[])
parser.add_argument('--iam-roles', nargs='+', default=[])
parser.add_argument('--iam-groups', nargs='+', default=[])
parser.add_argument('--iam-users', nargs='+', default=[])
#instance_profile_arn = ARN(role["InstanceProfileArn"])
#path = os.path.join(instance_profile_arn.resource, args.secret_name)
#print(s3.Bucket(args.bucket_name).Object(path).get())
