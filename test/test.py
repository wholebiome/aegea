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
        cmd = kwargs.get("args", args[0])
        print('Running "{}"'.format(cmd), file=sys.stderr)
        expect = kwargs.pop("expect", [dict(exit_codes=[os.EX_OK], stdout=None, stderr=None)])
        process = subprocess.Popen(stdin=kwargs.get("stdin", subprocess.PIPE), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, *args, **kwargs)
        out, err = process.communicate()
        exit_code = process.poll()
        out = out.decode(sys.stdin.encoding)
        err = err.decode(sys.stdin.encoding)
        def match(exit_code, out, err, expected):
            exit_ok = exit_code in expected["exit_codes"]
            stdout_ok = re.search(expected.get("stdout") or "", out)
            stderr_ok = re.search(expected.get("stderr") or "", err)
            return exit_ok and stdout_ok and stderr_ok
        if not any(match(exit_code, out, err, exp) for exp in expect):
            print(err)
            e = subprocess.CalledProcessError(exit_code, cmd, output=out)
            e.stdout, e.stderr = out, err
            raise e
        return out, err

    def test_basic_aegea_commands(self):
        #subprocess.check_call(["aegea"])
        self.call(["aegea", "--help"])
        self.call(["aegea", "pricing"])
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
            unauthorized_ok = [dict(exit_codes=[os.EX_OK]), dict(exit_codes=[1], stderr="(UnauthorizedOperation|AccessDenied)")]
            self.call(["aegea", subcommand] + args, expect=unauthorized_ok)

    def test_dry_run_commands(self):
        unauthorized_ok = [dict(exit_codes=[os.EX_OK]), dict(exit_codes=[1], stderr="UnauthorizedOperation")]
        self.call("aegea launch unittest --dry-run --no-verify-ssh-key-pem-file",
                  shell=True, expect=unauthorized_ok)
        self.call("aegea launch unittest --dry-run --spot --no-verify-ssh-key-pem-file",
                  shell=True, expect=unauthorized_ok)
        self.call("aegea launch unittest --dry-run --duration-hours 1 --no-verify-ssh-key-pem-file",
                  shell=True, expect=unauthorized_ok)
        self.call("aegea launch unittest --duration-hours 0.5 --min-mem-per-core-gb 6 --cores 2 --dry-run --no-verify-ssh-key-pem-file",
                  shell=True, expect=unauthorized_ok)
        self.call("aegea build_image i --dry-run --no-verify-ssh-key-pem-file",
                  shell=True, expect=unauthorized_ok)

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
    import xmlrunner
    unittest.main(testRunner=xmlrunner.XMLTestRunner(output='test-reports'))
