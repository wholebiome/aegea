#!/usr/bin/env python

import os, sys, glob, subprocess
from setuptools import setup, find_packages

try:
    # Git version extraction logic designed to be compatible with both semver and PEP 440
    version = subprocess.check_output(["git", "describe", "--tags", "--match", "v*.*.*"]).decode()
    version = version.strip("v\n").replace("-", "+", 1).replace("-", ".")
except:
    version = "0.0.0"

setup(
    name="aegea",
    version=version,
    url="https://github.com/kislyuk/aegea",
    license=open("LICENSE.md").readline().strip(),
    author="Andrey Kislyuk",
    author_email="kislyuk@gmail.com",
    description="Amazon Web Services Operator Interface",
    long_description=open("README.rst").read(),
    install_requires=[
        "setuptools",
        "boto3 >= 1.4.2, < 2",
        "argcomplete >= 1.8.2, < 2",
        "paramiko >= 2.1.1, < 3",
        "requests >= 2.12.4, < 3",
        "tweak >= 0.4.0, < 1",
        "keymaker >= 0.3.3, < 1",
        "pyyaml >= 3.11, < 4",
        "python-dateutil >= 2.5.3, < 3",
        "babel >= 2.3.4, < 3",
        "ipwhois >= 0.13.0, < 1",
        "github3.py == 1.0.0a4",
        "uritemplate.py == 3.0.2",
        "awscli >= 1.2.9"
    ],
    extras_require={
        ':python_version == "2.7"': [
            "enum34 >= 1.1.6, < 2",
            "ipaddress >= 1.0.17, < 2",
            "subprocess32 >= 3.2.7, < 4",
            "backports.statistics >= 0.1.0, < 1",
            "backports.shutil_get_terminal_size >= 1.0.0, < 2",
            "backports.functools_lru_cache >= 1.2.1, < 2"
        ],
        ':python_version < "2.7.9"': [
            "pyopenssl >= 16.2.0",
            "ndg-httpsclient >= 0.4.2, < 1"
        ]
    },
    tests_require=[
        "coverage",
        "flake8"
    ],
    packages=find_packages(exclude=["test"]),
    scripts=glob.glob("scripts/*"),
    platforms=["MacOS X", "Posix"],
    test_suite="test",
    include_package_data=True
)
