#!/usr/bin/env python
# coding: utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, unittest, collections, itertools, copy, re, subprocess, importlib, pkgutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import aegea
from aegea.util.aws import resolve_ami, SpotFleetBuilder
from aegea.util.exceptions import AegeaException

for importer, modname, is_pkg in pkgutil.iter_modules(aegea.__path__):
    importlib.import_module((aegea.__package__ or "aegea") + "." + modname)

class TestAegea(unittest.TestCase):
    def setUp(self):
        pass

    def call(self, *args, **kwargs):
        process = subprocess.Popen(stdin=kwargs.get("stdin", subprocess.PIPE), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, *args, **kwargs)
        out, err = process.communicate()
        exit_code = process.poll()
        out = out.decode(sys.stdin.encoding)
        err = err.decode(sys.stdin.encoding)
        if exit_code != os.EX_OK:
            print(err)
            cmd = kwargs.get("args", args[0])
            e = subprocess.CalledProcessError(exit_code, cmd, output=out)
            e.stderr = err
            raise e
        return out, err

    def call_unauthorized_ok(self, *args, **kwargs):
        message = kwargs.pop("message", "You are not authorized")
        try:
            self.call(*args, **kwargs)
        except Exception as e:
            if not (isinstance(e, subprocess.CalledProcessError) and message in e.stderr):
                raise

    def test_basic_aegea_commands(self):
        #subprocess.check_call(["aegea"])
        subprocess.check_call(["aegea", "--help"])
        subprocess.check_call(["aegea", "pricing"])
        for subcommand in aegea.parser._actions[-1].choices:
            args = []
            if subcommand in ("start", "stop", "reboot", "terminate", "console", "ssh", "grep"):
                args += ["--help"]
            elif subcommand in ("launch", "build_image"):
                args += ["--no-verify-ssh-key-pem-file", "--dry-run", "test"]
            elif subcommand == "rm":
                args += [resolve_ami()]
            elif subcommand == "secrets":
                args += ["ls"]
            elif subcommand == "pricing":
                args += ["AmazonEC2", "--json"]
            elif subcommand == "billing":
                args += ["--min-cost", "0.1"]
                if "AWS_DETAILED_BILLING_REPORTS_BUCKET" in os.environ:
                    args += ["--detailed-billing-reports-bucket", os.environ["AWS_DETAILED_BILLING_REPORTS_BUCKET"]]
            elif subcommand == "ls":
                args += ["--filter", "state=running"]
            self.call_unauthorized_ok(["aegea", subcommand] + args, message="Access Denied")

    def test_dry_run_commands(self):
        self.call_unauthorized_ok("aegea launch unittest --dry-run --no-verify-ssh-key-pem-file", shell=True)
        self.call_unauthorized_ok("aegea launch unittest --dry-run --spot --no-verify-ssh-key-pem-file", shell=True)
        self.call_unauthorized_ok("aegea launch unittest --dry-run --duration-hours 1 --no-verify-ssh-key-pem-file", shell=True)
        self.call_unauthorized_ok("aegea launch unittest --duration-hours 0.5 --min-mem-per-core-gb 6 --cores 2 --dry-run --no-verify-ssh-key-pem-file",
                                  shell=True)
        self.call_unauthorized_ok("aegea build_image i --dry-run --no-verify-ssh-key-pem-file", shell=True)

    def test_spot_fleet_builder(self):
        builder = SpotFleetBuilder(launch_spec={})
        self.assertEqual(set(spec["InstanceType"] for spec in builder.launch_specs()),
                         {"c3.large", "c4.large", "m3.large", "m4.large", "m3.medium"})
        self.assertEqual(set(spec["InstanceType"] for spec in builder.launch_specs(max_overprovision=4)),
                         {"c3.large", "c4.large", "m3.large", "m4.large", "m3.medium", "m4.xlarge", "c3.xlarge", "c4.xlarge", "m3.xlarge"})
        with self.assertRaises(AegeaException):
            builder = SpotFleetBuilder(launch_spec={}, min_cores_per_instance=16)
        builder = SpotFleetBuilder(launch_spec={}, cores=16, min_cores_per_instance=16)
        self.assertEqual(set(spec["InstanceType"] for spec in builder.launch_specs()),
                         {'c3.4xlarge', 'c4.8xlarge', 'c4.4xlarge', 'm4.10xlarge', 'c3.8xlarge', 'm4.4xlarge'})
        builder = SpotFleetBuilder(launch_spec={}, cores=16, min_cores_per_instance=16, min_mem_per_core_gb=6)
        self.assertEqual(set(spec["InstanceType"] for spec in builder.launch_specs()),
                         {'r3.4xlarge', 'r3.8xlarge', 'd2.4xlarge', 'i2.8xlarge', 'd2.8xlarge', 'i2.4xlarge'})
        builder = SpotFleetBuilder(launch_spec={}, cores=32, min_cores_per_instance=32, min_mem_per_core_gb=6)
        self.assertEqual(set(spec["InstanceType"] for spec in builder.launch_specs()),
                         {'r3.8xlarge', 'i2.8xlarge', 'd2.8xlarge'})
        # TODO: This will need updating when X1s come out
        builder = SpotFleetBuilder(launch_spec={}, cores=32, min_cores_per_instance=16, min_mem_per_core_gb=8)
        self.assertFalse(set(spec["InstanceType"] for spec in builder.launch_specs()))
        builder = SpotFleetBuilder(launch_spec={}, cores=4, gpus_per_instance=1)
        self.assertEqual(set(spec["InstanceType"] for spec in builder.launch_specs()), {"g2.2xlarge"})
        builder = SpotFleetBuilder(launch_spec={}, cores=16, gpus_per_instance=4)
        self.assertEqual(set(spec["InstanceType"] for spec in builder.launch_specs()), {"g2.8xlarge"})

if __name__ == '__main__':
    unittest.main()
