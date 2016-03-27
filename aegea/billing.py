"""
View detailed billing reports.

Detailed billing reports can be configured at https://console.aws.amazon.com/billing/home#/preferences.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json, zipfile, csv, io
from io import BytesIO, TextIOWrapper
from datetime import datetime

import boto3, requests
from botocore.exceptions import ClientError

from . import register_parser
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.aws import ARN

def filter_line_items(args):
    def filter_fn(item):
        if args.min_cost and float(item["Cost"]) < args.min_cost:
            return False
        return True
    return filter_fn

def billing(args):
    s3 = boto3.resource("s3")
    iam = boto3.resource("iam")
    account_id = ARN(iam.CurrentUser().user.arn).account_id
    args.detailed_billing_reports_bucket = args.detailed_billing_reports_bucket.format(account_id=account_id)
    now = datetime.utcnow()
    report = "{account_id}-aws-billing-detailed-line-items-with-resources-and-tags-{year}-{month}.csv.zip"
    report = report.format(account_id=account_id, year=args.year or now.year, month="%02d" % (args.month or now.month))
    try:
        billing_object = s3.Bucket(args.detailed_billing_reports_bucket).Object(report)
        billing_object_body = billing_object.get()["Body"]
    except ClientError as e:
        console_url = "https://console.aws.amazon.com/billing/home#/preferences"
        msg = "Can't get detailed billing report {} from bucket {} in account {}: {}. Go to {} to set up detailed billing."
        sys.exit(msg.format(report, args.detailed_billing_reports_bucket, account_id, e, console_url))
    zbuf = BytesIO(billing_object_body.read())
    with zipfile.ZipFile(zbuf) as zfile:
        with TextIOWrapper(zfile.open(report.rstrip(".zip"))) as fh:
            reader = csv.DictReader(fh)
            page_output(tabulate(filter(filter_line_items(args), reader), args))

parser = register_parser(billing, help='List contents of AWS detailed billing reports', description=__doc__)
parser.add_argument("--columns", nargs="+")
#parser.add_argument("--sort-by")
parser.add_argument("--year", type=int, help="Year to get billing reports for. Defaults to current year")
parser.add_argument("--month", type=int, help="Month (numeral) to get billing reports for. Defaults to current month")
parser.add_argument("--detailed-billing-reports-bucket", help="Name of S3 bucket to retrieve detailed billing reports from")
parser.add_argument("--min-cost", type=float, help="Omit billing line items below this cost")
