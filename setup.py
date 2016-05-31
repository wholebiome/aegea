#!/usr/bin/env python

import os, sys, glob, subprocess
from setuptools import setup, find_packages

try:
    # Git version extraction logic designed to be compatible with both semver and PEP 440
    version = subprocess.check_output(["git", "describe", "--tags", "--match", "v*.*.*"])
    version = version.strip("v\n").replace("-", "+", 1).replace("-", ".")
except:
    version = "0.0.0"

setup(
    name='aegea',
    version=version,
    url='https://github.com/kislyuk/aegea',
    license=open('LICENSE.md').readline().strip(),
    author='Andrey Kislyuk',
    author_email='kislyuk@gmail.com',
    description='Amazon Web Services Operator Interface',
    long_description=open('README.rst').read(),
    install_requires=[
        'setuptools',
        'boto3 >= 1.3.0',
        'argcomplete >= 1.1.0',
        'paramiko >= 1.16.0',
        'requests >= 2.9.1',
        'tweak >= 0.3.2',
        'keymaker >= 0.1.7',
        'pyyaml >= 3.11',
        'python-dateutil >= 2.1',
    ],
    extras_require={
        ':python_version == "2.7"': [
            'enum34 >= 1.0.4',
            'ipaddress >= 1.0.16',
            'backports.statistics >= 0.1.0'
        ]
    },
    tests_require=[
        'coverage',
        'flake8',
        'unittest-xml-reporting'
    ],
    packages=find_packages(exclude=['test']),
    scripts=glob.glob('scripts/*'),
    platforms=['MacOS X', 'Posix'],
    test_suite='test',
    include_package_data=True
)
