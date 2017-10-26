from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json, time, base64, argparse, io, gzip
from collections import OrderedDict

from botocore.exceptions import ClientError

from . import register_parser, logger, config, __version__
from .util.aws import ARN, clients, resources, expect_error_codes, ensure_iam_role, IAMPolicyBuilder
from .util.cloudinit import get_bootstrap_files, encode_cloud_config_payload
from .batch import submit, submit_parser, bash_cmd_preamble

dockerfile = """
FROM {base_image}
MAINTAINER {maintainer}
LABEL {label}
ENV CLOUD_CONFIG_B64 {cloud_config_b64}
RUN {run}
"""

def get_dockerfile(args):
    if args.dockerfile:
        return io.open(args.dockerfile, "rb").read()
    else:
        cmd = bash_cmd_preamble + [
            "apt-get update -qq",
            "apt-get install -qqy cloud-init net-tools",
            "echo $CLOUD_CONFIG_B64 | base64 --decode > /etc/cloud/cloud.cfg.d/99_aegea.cfg",
            "cloud-init init",
            "cloud-init modules --mode=config",
            "cloud-init modules --mode=final"
        ]
        return dockerfile.format(base_image=args.base_image,
                                 maintainer=ARN.get_iam_username(),
                                 label=" ".join(args.tags),
                                 cloud_config_b64=base64.b64encode(get_cloud_config(args)).decode(),
                                 run=json.dumps(cmd)).encode()

def encode_dockerfile(args):
    with io.BytesIO() as buf:
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(get_dockerfile(args))
            gz.close()
        return base64.b64encode(buf.getvalue()).decode()

def get_cloud_config(args):
    cloud_config_data = OrderedDict(packages=args.packages,
                                    write_files=get_bootstrap_files(args.rootfs_skel_dirs),
                                    runcmd=args.commands)
    cloud_config_data.update(dict(args.cloud_config_data))
    cloud_cfg_d = {
        "datasource_list": ["None"],
        "datasource": {
            "None": {
                "userdata_raw": encode_cloud_config_payload(cloud_config_data, gzip=False)
            }
        }
    }
    return json.dumps(cloud_cfg_d).encode()

def ensure_ecr_repo(name, read_access=None):
    try:
        clients.ecr.create_repository(repositoryName=name)
    except clients.ecr.exceptions.RepositoryAlreadyExistsException:
        pass
    policy = IAMPolicyBuilder(principal=dict(AWS=read_access),
                              action=["ecr:GetDownloadUrlForLayer",
                                      "ecr:BatchGetImage",
                                      "ecr:BatchCheckLayerAvailability"])
    if read_access:
        clients.ecr.set_repository_policy(repositoryName=name, policyText=str(policy))

def build_docker_image(args):
    for key, value in config.build_image.items():
        getattr(args, key).extend(value)
    args.tags += ["AegeaVersion={}".format(__version__),
                  'description="Built by {} for {}"'.format(__name__, ARN.get_iam_username())]
    ensure_ecr_repo(args.name, read_access=args.read_access)
    submit_args = submit_parser.parse_args([
        "--command",
        "set -euo pipefail",
        "apt-get update -qq",
        "apt-get install -qqy python-pip",
        "apt-get -qqy install apt-transport-https ca-certificates curl software-properties-common",
        "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -",
        "apt-key fingerprint 0EBFCD88",
        "add-apt-repository \"deb [arch=amd64] https://download.docker.com/linux/ubuntu  $(lsb_release -cs) stable\"",
        "apt-get update",
        "apt-get install -qqy docker-ce",
        "pip install -q awscli",
        "cd $(mktemp -d)",
        "aws configure set default.region $AWS_DEFAULT_REGION",
        "$(aws ecr get-login | sed -e 's/-e none//')",
        'echo "$DOCKERFILE_B64GZ" | base64 --decode | gunzip > Dockerfile',
        'TAG="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/${REPO}:${TAG}"',
        'docker build -t "$TAG" .',
        'docker push "$TAG"'
    ])
    submit_args.volumes = [["/var/run/docker.sock", "/var/run/docker.sock"]]
    submit_args.privileged = True
    submit_args.watch = True
    submit_args.dry_run = args.dry_run
    submit_args.image = args.builder_image
    submit_args.environment = [
        dict(name="TAG", value="latest"),
        dict(name="REPO", value=args.name),
        dict(name="DOCKERFILE_B64GZ", value=encode_dockerfile(args)),
        dict(name="AWS_DEFAULT_REGION", value=ARN.get_region()),
        dict(name="AWS_ACCOUNT_ID", value=ARN.get_account_id())
    ]
    builder_iam_role = ensure_iam_role(__name__, trust=["ecs-tasks"], policies=args.builder_iam_policies)
    submit_args.job_role = builder_iam_role.name
    job = submit(submit_args)
    return dict(job=job)

parser = register_parser(build_docker_image, help="Build an Elastic Container Registry Docker image")
parser.add_argument("name")
parser.add_argument("--read-access", nargs="*",
                    help="AWS account IDs or IAM principal ARNs to grant read access. Use '*' to grant to all.")
# Using 14.04 here to prevent "client version exceeds server version" error because ECS host docker is too old
parser.add_argument("--builder-image", default="ubuntu:14.04", help=argparse.SUPPRESS)
parser.add_argument("--builder-iam-policies", nargs="+",
                    default=["AmazonEC2FullAccess", "AmazonS3FullAccess", "AmazonEC2ContainerRegistryPowerUser"])
parser.add_argument("--tags", nargs="+", default=[], metavar="NAME=VALUE", help="Tag resulting image with these tags")
parser.add_argument("--cloud-config-data", type=json.loads)
parser.add_argument("--dockerfile")
parser.add_argument("--dry-run", action="store_true", help="Gather arguments and stop short of building the image")
