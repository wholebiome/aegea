from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, time, csv, json
import boto3
from botocore.exceptions import ClientError
import dateutil.parser
from datetime import datetime, timedelta

from . import register_parser, logger, config
from .util.aws import (get_user_data, ensure_vpc, ensure_subnet, ensure_ingress_rule, ensure_security_group, DNSZone,
                       ensure_instance_profile, add_tags, resolve_security_group, get_bdm, resolve_instance_id,
                       expect_error_codes, resolve_ami)
from .util.printing import RED, GREEN, WHITE, page_output, format_table

class Auditor:
    _credential_report = None
    @property
    def credential_report(self):
        if self._credential_report is None:
            iam = boto3.client("iam")
            iam.generate_credential_report()
            while True:
                try:
                    self._credential_report = iam.get_credential_report()
                    break
                except ClientError as e:
                    expect_error_codes(e, "ReportInProgress")
        return csv.DictReader(self._credential_report["Content"].decode("utf-8").splitlines())

    def parse_date(self, d):
        return dateutil.parser.parse(d, ignoretz=True)

    def audit_1_1(self):
        """1.1 Avoid the use of the "root" account (Scored)"""
        for row in self.credential_report:
            if row["user"] == "<root_account>":
                for field in "password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date":
                    if row[field] != "N/A" and self.parse_date(row[field]) > datetime.utcnow() - timedelta(days=1):
                        raise Exception("Root account last used less than a day ago ({})".format(field))

    def audit_1_2(self):
        """1.2 Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)"""
        for row in self.credential_report:
            if row["user"] == "<root_account>" or json.loads(row["password_enabled"]):
                if not json.loads(row["mfa_active"]):
                    raise Exception("Account {} has a console password but no MFA".format(row["user"]))

    def audit_1_3(self):
        """1.3 Ensure credentials unused for 90 days or greater are disabled (Scored)"""
        for row in self.credential_report:
            for access_key in "1", "2":
                if json.loads(row["access_key_{}_active".format(access_key)]):
                    last_used = row["access_key_{}_last_used_date".format(access_key)]
                    if last_used != "N/A" and self.parse_date(last_used) < datetime.utcnow() - timedelta(days=90):
                        raise Exception("Active access key {} in account {} last used over 90 days ago".format(access_key, row["user"]))

    def audit_1_4(self):
        """1.4 Ensure access keys are rotated every 90 days or less (Scored)"""
        for row in self.credential_report:
            for access_key in "1", "2":
                if json.loads(row["access_key_{}_active".format(access_key)]):
                    last_rotated = row["access_key_{}_last_rotated".format(access_key)]
                    if self.parse_date(last_rotated) < datetime.utcnow() - timedelta(days=90):
                        raise Exception("Active access key {} in account {} last rotated over 90 days ago".format(access_key, row["user"]))

def audit(args):
    auditor = Auditor()
    table = []
    for method_name in dir(auditor):
        if method_name.startswith("audit"):
            method = getattr(auditor, method_name)
            try:
                method()
                table.append([GREEN("PASS"), method.__doc__])
            except Exception as e:
                logger.debug("%s: %s", method, e)
                table.append([RED("FAIL"), method.__doc__])
    # TODO: WHITE("NO TEST")
    page_output(format_table(table, column_names=["Result", "Test"], max_col_width=120))

parser = register_parser(audit, help='Generate a security report using the CIS AWS Foundations Benchmark')
tests = """1 Identity and Access Management
1.1 Avoid the use of the "root" account (Scored)
1.2 Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)
1.3 Ensure credentials unused for 90 days or greater are disabled (Scored)
1.4 Ensure access keys are rotated every 90 days or less (Scored)
1.5 Ensure IAM password policy requires at least one uppercase letter (Scored)
1.6 Ensure IAM password policy require at least one lowercase letter (Scored)
1.7 Ensure IAM password policy require at least one symbol (Scored)
1.8 Ensure IAM password policy require at least one number (Scored)
1.9 Ensure IAM password policy requires minimum length of 14 or greater (Scored)
1.10 Ensure IAM password policy prevents password reuse (Scored)
1.11 Ensure IAM password policy expires passwords within 90 days or less (Scored)
1.12 Ensure no root account access key exists (Scored)
1.13 Ensure hardware MFA is enabled for the "root" account (Scored)
1.14 Ensure security questions are registered in the AWS account (Not Scored)
1.15 Ensure IAM policies are attached only to groups or roles (Scored)
2 Logging
2.1 Ensure CloudTrail is enabled in all regions (Scored)
2.2 Ensure CloudTrail log file validation is enabled (Scored)
2.3 Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)
2.4 Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)
2.5 Ensure AWS Config is enabled in all regions (Scored)
2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)
2.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)
2.8 Ensure rotation for customer created CMKs is enabled (Scored)
3 Monitoring
3.1 Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)
3.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)
3.3 Ensure a log metric filter and alarm exist for usage of "root" account (Scored)
3.4 Ensure a log metric filter and alarm exist for IAM policy changes (Scored)
3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)
3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)
3.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)
3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)
3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)
3.10 Ensure a log metric filter and alarm exist for security group changes (Scored)
3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)
3.12 Ensure a log metric filter and alarm exist for changes to network gateways (Scored)
3.13 Ensure a log metric filter and alarm exist for route table changes (Scored)
3.14 Ensure a log metric filter and alarm exist for VPC changes (Scored)
3.15 Ensure security contact information is registered (Scored)
3.16 Ensure appropriate subscribers to each SNS topic (Not Scored)
4 Networking
4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)
4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)
4.3 Ensure VPC Flow Logging is Enabled in all Applicable Regions (Scored)
4.4 Ensure the default security group restricts all traffic (Scored)
"""
