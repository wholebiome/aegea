"""
Manage IAM users, groups, roles, and policies
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, collections

from . import config
from .ls import register_parser, register_listing_parser
from .util import Timestamp, paginate, hashabledict
from .util.printing import page_output, tabulate, BOLD
from .util.aws import resources, clients, ensure_iam_group, IAMPolicyBuilder

def iam(args):
    iam_parser.print_help()

iam_parser = register_parser(iam, help=__doc__.strip())

def configure(args):
    for group, policies in config.managed_iam_groups.items():
        print("Creating group", group)
        ensure_iam_group(group, policies=[(IAMPolicyBuilder(**p) if isinstance(p, collections.Mapping) else p) for p in policies])
        msg = 'Created group {g}. Use the AWS console or "aws iam add-user-to-group --user-name USER --group-name {g}" to add users to it.' # noqa
        print(BOLD(msg.format(g=group)))

parser_configure = register_parser(configure, parent=iam_parser, help="Set up aegea-specific IAM groups and policies")

def get_policies_for_principal(cell, row):
    return ", ".join([p.policy_name for p in row.policies.all()] + [p.policy_name for p in row.attached_policies.all()])

def users(args):
    current_user = resources.iam.CurrentUser()

    def mark_cur_user(cell, row):
        return ">>>" if row.user_id == current_user.user_id else ""
    users = list(resources.iam.users.all())
    for user in users:
        user.cur = ""
    cell_transforms = {"cur": mark_cur_user, "policies": get_policies_for_principal}
    page_output(tabulate(users, args, cell_transforms=cell_transforms))

parser = register_listing_parser(users, parent=iam_parser, help="List IAM users")

def groups(args):
    page_output(tabulate(resources.iam.groups.all(), args, cell_transforms={"policies": get_policies_for_principal}))

parser = register_listing_parser(groups, parent=iam_parser, help="List IAM groups")

def roles(args):
    page_output(tabulate(resources.iam.roles.all(), args, cell_transforms={"policies": get_policies_for_principal}))

parser = register_listing_parser(roles, parent=iam_parser, help="List IAM roles")

def policies(args):
    page_output(tabulate(resources.iam.policies.all(), args))

parser = register_listing_parser(policies, parent=iam_parser, help="List IAM policies")
parser.add_argument("--sort-by")
