from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json, time, base64, argparse
from collections import OrderedDict
from io import open

from botocore.exceptions import ClientError

from . import register_parser, logger, config, __version__
from .util.aws import ARN, clients, resources, expect_error_codes
from .util.crypto import ensure_ssh_key, new_ssh_key, add_ssh_host_key_to_known_hosts, get_ssh_key_filename
from .build_ami import get_bootstrap_files
from .batch import submit, submit_parser

dockerfile = """
FROM {base_image}
MAINTAINER {maintainer}
LABEL {label}
ENV CLOUD_CONFIG_B64 {cloud_config_b64}
RUN {run}
"""

def get_dockerfile(args):
    if args.dockerfile:
        return open(args.dockerfile, "rb").read()
    else:
        cmd = ["/bin/bash", "-c", ";".join([
            "apt-get update --quiet",
            "apt-get install --quiet --yes cloud-init net-tools",
            "echo $CLOUD_CONFIG_B64 | base64 --decode > /etc/cloud/cloud.cfg.d/99_aegea.cfg"])
        ]
        return dockerfile.format(base_image=args.base_image,
                                 maintainer=resources.iam.CurrentUser().user.name,
                                 label=" ".join(args.tags),
                                 cloud_config_b64=base64.b64encode(get_cloud_config(args)).decode(),
                                 run=json.dumps(cmd)).encode()

def get_cloud_config(args):
    cloud_config_data = OrderedDict(packages=args.packages,
                                    write_files=get_bootstrap_files(args.rootfs_skel_dirs),
                                    runcmd=args.commands)
    cloud_config_data.update(dict(args.cloud_config_data))
    cloud_cfg_d = {
        "datasource_list": ["None"],
        "datasource": {
            "None": {
                "userdata_raw": "#cloud-config\n" + json.dumps(cloud_config_data)
            }
        }
    }
    return json.dumps(cloud_cfg_d).encode()

def ensure_ecr_repo(name):
    try:
        clients.ecr.create_repository(repositoryName=name)
    except ClientError as e:
        expect_error_codes(e, "RepositoryAlreadyExistsException")

def build_docker_image(args):
    args.tags += ["AegeaVersion={}".format(__version__)]
    ensure_ecr_repo(args.mission)
    submit_args = submit_parser.parse_args([
        "--command",
        "set -euxo pipefail",
        "apt-get update --quiet",
        "apt-get install --quiet --yes docker.io python-pip",
        "pip install awscli",
        "cd $(mktemp -d)",
        "aws configure set default.region $AWS_DEFAULT_REGION",
        "$(aws ecr get-login)",
        'echo "$DOCKERFILE_B64" | base64 --decode > Dockerfile',
        'TAG="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/${REPO}:${TAG}"',
        'docker build -t "$TAG" .',
        'docker push "$TAG"'
    ])
    submit_args.volumes = [["/var/run/docker.sock", "/var/run/docker.sock"]]
    submit_args.privileged = True
    submit_args.watch = True
    submit_args.image = args.builder_image
    submit_args.environment = [
        dict(name="TAG", value="latest"),
        dict(name="REPO", value=args.mission),
        dict(name="DOCKERFILE_B64", value=base64.b64encode(get_dockerfile(args)).decode()),
        dict(name="AWS_DEFAULT_REGION", value=ARN.get_region()),
        dict(name="AWS_ACCOUNT_ID", value=ARN.get_account_id())
    ]
    job = submit(submit_args)
    #description = "Built by {} for {}".format(__name__, resources.iam.CurrentUser().user.name)
    #volumes
    return dict(job=job)

parser = register_parser(build_docker_image, help="Build an Elastic Container Registry Docker image")
parser.add_argument("mission")
# Using 14.04 here to prevent "client version exceeds server version" error because ECS host docker is too old
parser.add_argument("--builder-image", default="ubuntu:14.04", help=argparse.SUPPRESS)
parser.add_argument("--tags", nargs="+", default=[], metavar="NAME=VALUE", help="Tag resulting image with these tags")
parser.add_argument("--cloud-config-data", type=json.loads)
parser.add_argument("--dockerfile")
