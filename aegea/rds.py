"""
RDS FTW
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, getpass
from datetime import datetime

from . import register_parser
from .util import Timestamp, paginate
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.aws import ARN, resources, clients

def rds(args):
    rds_parser.print_help()

rds_parser = register_parser(rds, help='Manage RDS resources', description=__doc__,
                             formatter_class=argparse.RawTextHelpFormatter)

def ls(args):
    page_output(tabulate(paginate(clients.rds.get_paginator('describe_db_instances')), args))

ls_parser = register_parser(ls, parent=rds_parser)

def create(args):
    tags = dict([tag.split("=", 1) for tag in args.tags])
    clients.rds.create_db_instance(DBInstanceIdentifier=args.name,
                                   AllocatedStorage=args.storage,
                                   DBName=args.name,
                                   Engine=args.engine,
                                   StorageType=args.storage_type,
                                   StorageEncrypted=True,
                                   AutoMinorVersionUpgrade=True,
                                   MultiAZ=False,
                                   MasterUsername=args.master_username or getpass.getuser(),
                                   MasterUserPassword=args.master_user_password,
                                   VpcSecurityGroupIds=args.security_groups,
                                   DBInstanceClass=args.db_instance_class,
                                   Tags=[dict(Key=k, Value=v) for k, v in tags.items()])
    clients.rds.get_waiter('db_instance_available').wait(DBInstanceIdentifier=args.name)

create_parser = register_parser(create, parent=rds_parser)
create_parser.add_argument('name')
create_parser.add_argument('--engine')
create_parser.add_argument('--storage', type=int)
create_parser.add_argument('--storage-type')
create_parser.add_argument('--master-username')
create_parser.add_argument('--master-user-password', '--password', required=True)
create_parser.add_argument('--db-instance-class')
create_parser.add_argument('--tags', nargs="+", default=[])
create_parser.add_argument('--security-groups', nargs="+", default=[])

def delete(args):
    clients.rds.delete_db_instance(DBInstanceIdentifier=args.name, SkipFinalSnapshot=True)

delete_parser = register_parser(delete, parent=rds_parser)

def snapshot(args):
    print("s")

snapshot_parser = register_parser(snapshot, parent=rds_parser)

def restore(args):
    print("r")

restore_parser = register_parser(restore, parent=rds_parser)
