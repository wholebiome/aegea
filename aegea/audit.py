from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, time, datetime
import boto3

from . import register_parser, logger, config

from .util import wait_for_port, validate_hostname
from .util.aws import (get_user_data, ensure_vpc, ensure_subnet, ensure_ingress_rule, ensure_security_group, DNSZone,
                       ensure_instance_profile, add_tags, resolve_security_group, get_bdm, resolve_instance_id,
                       expect_error_codes, resolve_ami)
from .util.crypto import new_ssh_key, add_ssh_host_key_to_known_hosts, ensure_ssh_key
from .util.exceptions import AegeaException
from botocore.exceptions import ClientError

def audit(args):
    pass

parser = register_parser(audit, help='Generate a security report')
