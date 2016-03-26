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

    def test_basic_aegea_commands(self):
        #subprocess.check_call(["aegea"])
        subprocess.check_call(["aegea", "--help"])
        for subcommand in aegea.parser._actions[-1].choices:
            args = []
            if subcommand in ("start", "stop", "reboot", "terminate", "console", "ssh"):
                args += ["--help"]
            elif subcommand in ("launch", "build_image"):
                args += ["--dry-run", "test"]
            elif subcommand == "rm":
                args += [resolve_ami()]
            elif subcommand == "secrets":
                args += ["ls"]
            elif subcommand == "pricing":
                args += ["AmazonEC2"]
            subprocess.check_call(["aegea", subcommand] + args)

    def test_dry_run_commands(self):
        subprocess.check_call("aegea launch unittest --dry-run", shell=True)
        subprocess.check_call("aegea launch unittest --dry-run --spot", shell=True)
        subprocess.check_call("aegea launch unittest --dry-run --spot-duration-hours 1", shell=True)
        subprocess.check_call("aegea launch unittest --spot-duration-hours 0.5 --min-mem-per-core-gb 6 --cores 2 --dry-run",
                              shell=True)
        subprocess.check_call("aegea build_image i --dry-run", shell=True)

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
