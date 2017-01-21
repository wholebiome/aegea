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

Examples
========
Using ``aegea secrets`` to generate and save an SSH key pair accessible by instances launched by ``aegea launch``::

    aegea secrets put deploy.foo.bar --generate-ssh-key --iam-role aegea.launch > secrets.out.json
    jq --raw-output .ssh_public_key < secrets.out.json > deploy.foo.bar.pub

    eval $(ssh-agent -s)
    aegea-get-secret deploy.bitbucket.my-private-repo | ssh-add /dev/stdin
    git clone git@bitbucket.org:my-org/my-private-repo.git

Using ``aegea secrets`` to save an API key (password) accessible by the IAM group ``space_marines``::

    RAILGUN_PASSWORD=passw0rd aegea secrets put RAILGUN_PASSWORD --iam-group space_marines

"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, subprocess, json, copy

from botocore.exceptions import ClientError

from . import register_parser
from .util.aws import ARN, IAMPolicyBuilder, resources, expect_error_codes, ensure_iam_policy
from .util.printing import page_output, tabulate
from .util.exceptions import AegeaException
from .util.crypto import new_ssh_key, hostkey_line, key_fingerprint
from .util.compat import StringIO

def build_s3_bucket_policy(account_id, bucket):
    resource = "arn:aws:s3:::" + bucket + "/user/${aws:userid}/*"
    return IAMPolicyBuilder(principal={"AWS": account_id}, action="s3:GetObject", resource=resource).policy

def build_iam_policy(principal, bucket):
    resource = "arn:aws:s3:::{bucket}/{principal}/*".format(bucket=bucket, principal=principal)
    return IAMPolicyBuilder(action="s3:GetObject", resource=resource)

def ensure_bucket():
    account_id = ARN.get_account_id()
    bucket_name = "credentials-{}".format(account_id)
    bucket = resources.s3.Bucket(bucket_name)
    try:
        bucket.load()
    except ClientError as e:
        expect_error_codes(e, "404")
        bucket.create()
        policy = bucket.Policy()
        policy.put(Policy=json.dumps(build_s3_bucket_policy(account_id, bucket.name)))
    return bucket

def get_secret_object(principal, secret_name):
    bucket = ensure_bucket()
    return bucket.Object(os.path.join(ARN(principal.arn).resource, secret_name))

def parse_principal(args):
    if args.instance_profile:
        return resources.iam.Role(resources.iam.InstanceProfile(args.instance_profile).roles[0])
    elif args.iam_role:
        return resources.iam.Role(args.iam_role)
    elif args.iam_group:
        return resources.iam.Group(args.iam_group)
    elif args.iam_user:
        return resources.iam.User(args.iam_user)
    else:
        raise AegeaException('Please specify a principal with "--instance-profile" or "--iam-{role,user,group}".')

def ensure_policy(principal, bucket):
    # Users are subject to the /user/${aws:userid} parametric bucket policy, so don't get policies attached to them
    if principal.__class__.__name__ != "iam.User":
        resource = "arn:aws:s3:::{bucket}/{prefix}/*".format(bucket=bucket.name, prefix=ARN(principal.arn).resource)
        policy_name = __name__ + "." + ARN(principal.arn).resource.replace("/", ".")
        policy_doc = IAMPolicyBuilder(action="s3:GetObject", resource=resource)
        policy = ensure_iam_policy(policy_name, policy_doc)
        principal.attach_policy(PolicyArn=policy.arn)

def secrets(args):
    secrets_parser.print_help()

secrets_parser = register_parser(secrets,
                                 help="Manage application credentials (secrets)",
                                 description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)

def ls(args):
    cell_transforms = {"owner": lambda x, r: x.get("DisplayName") if x else None}
    page_output(tabulate(ensure_bucket().objects.all(), args, cell_transforms=cell_transforms))

ls_parser = register_parser(ls, parent=secrets_parser)
ls_parser.add_argument("--columns", nargs="+",
                       default=["bucket_name", "key", "owner", "size", "last_modified", "storage_class"])

def put(args):
    if args.generate_ssh_key:
        ssh_key = new_ssh_key()
        buf = StringIO()
        ssh_key.write_private_key(buf)
        secret_value = buf.getvalue()
    elif args.secret_name in os.environ:
        secret_value = os.environ[args.secret_name]
    else:
        secret_value = sys.stdin.read()
    ensure_policy(parse_principal(args), ensure_bucket())
    secret_object = get_secret_object(parse_principal(args), args.secret_name)
    secret_object.put(Body=secret_value.encode(), ServerSideEncryption="AES256")
    if args.generate_ssh_key:
        return dict(ssh_public_key=hostkey_line(hostnames=[], key=ssh_key).strip(),
                    ssh_key_fingerprint=key_fingerprint(ssh_key))

put_parser = register_parser(put, parent=secrets_parser)
put_parser.add_argument("--generate-ssh-key", action="store_true",
                        help="Generate a new SSH key pair and write the private key as the secret value; write the public key to stdout")  # noqa

def get(args):
    secret_object = get_secret_object(parse_principal(args), args.secret_name)
    sys.stdout.write(secret_object.get()["Body"].read().decode("utf-8"))

get_parser = register_parser(get, parent=secrets_parser)

def delete(args):
    get_secret_object(parse_principal(args), args.secret_name).delete()

delete_parser = register_parser(delete, parent=secrets_parser)

for parser in put_parser, get_parser, delete_parser:
    parser.add_argument("secret_name",
                        help="List the secret name. For put, pass the secret value on stdin, or via an environment variable with the same name as the secret.")  # noqa
    parser.add_argument("--instance-profile")
    parser.add_argument("--iam-role")
    parser.add_argument("--iam-group")
    parser.add_argument("--iam-user",
                        help="Name of IAM instance profile, role, group, or user who will be granted access to secret")
