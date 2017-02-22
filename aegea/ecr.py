"""
Manage AWS Elastic Container Registry (ECR) resources.

Use ``aws ecr create-repository`` and ``aws ecr delete-repository`` to manage ECR repositories.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse

from botocore.exceptions import ClientError

from .ls import register_parser, register_listing_parser
from .util import Timestamp, paginate, hashabledict
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.exceptions import AegeaException
from .util.compat import lru_cache
from .util.aws import (ARN, resources, clients, resolve_instance_id, resolve_security_group, get_elb_dns_aliases,
                       DNSZone, ensure_vpc, expect_error_codes)

def ecr(args):
    ecr_parser.print_help()

ecr_parser = register_parser(ecr, help="Manage Elastic Container Registry resources", description=__doc__,
                             formatter_class=argparse.RawTextHelpFormatter)

def ls(args):
    table = []
    describe_repositories_args = dict(repositoryNames=args.repositories) if args.repositories else {}
    for repo in paginate(clients.ecr.get_paginator("describe_repositories"), **describe_repositories_args):
        orig_len = len(table)
        for image in paginate(clients.ecr.get_paginator("describe_images"), repositoryName=repo["repositoryName"]):
            table.append(dict(image, **repo))
        if len(table) == orig_len:
            table.append(repo)
    page_output(tabulate(table, args))

parser = register_listing_parser(ls, parent=ecr_parser, help="List ECR repos and images")
parser.add_argument("repositories", nargs="*")

def ecr_image_name_completer(**kwargs):
    return (r["repositoryName"] for r in paginate(clients.ecr.get_paginator("describe_repositories")))
