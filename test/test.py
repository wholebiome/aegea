#!/usr/bin/env python
# coding: utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, unittest, collections, itertools, copy, re, subprocess

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import aegea

class TestAegea(unittest.TestCase):
    def setUp(self):
        pass

    def test_basic_aegea_commands(self):
        subprocess.check_call(["aegea", "--help"])
        subprocess.check_call(["aegea", "ls"])

if __name__ == '__main__':
    unittest.main()
