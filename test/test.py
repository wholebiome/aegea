#!/usr/bin/env python
# coding: utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, unittest, collections, itertools, copy, re, subprocess, importlib, pkgutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import aegea
from aegea.util.aws import resolve_ami

for importer, modname, is_pkg in pkgutil.iter_modules(aegea.__path__):
    importlib.import_module((aegea.__package__ or "aegea") + "." + modname)

class TestAegea(unittest.TestCase):
    def setUp(self):
        pass

    def test_basic_aegea_commands(self):
        subprocess.check_call(["aegea"])
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
            subprocess.check_call(["aegea", subcommand] + args)

if __name__ == '__main__':
    unittest.main()
