#!/usr/bin/env python

import os, sys, glob
from setuptools import setup, find_packages

setup(
    name='aegea',
    version='0.2.1',
    url='https://github.com/kislyuk/aegea',
    license='Proprietary',
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
        'tweak >= 0.1.2',
        'keymaker >= 0.1.7',
        'pyyaml >= 3.11'
    ],
    extras_require={
        ':python_version == "2.7"': ['enum34 >= 1.0.4', 'ipaddress >= 1.0.16'],
        ':python_version == "3.3"': ['enum34 >= 1.0.4']
    },
    packages=find_packages(exclude=['test']),
    scripts=glob.glob('scripts/*'),
    platforms=['MacOS X', 'Posix'],
    test_suite='test',
    include_package_data=True
)
