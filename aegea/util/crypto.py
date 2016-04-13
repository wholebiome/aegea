from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys
import boto3

from .. import logger

def new_ssh_key(bits=2048):
    from paramiko import RSAKey
    return RSAKey.generate(bits=bits)

def get_public_key_from_pair(key):
    return key.get_name() + " " + key.get_base64()

def host_key_fingerprint(key):
    return key.get_name() + " " + ":".join("{:02x}".format(i) for i in key.get_fingerprint())

def get_ssh_key_path(name):
    return os.path.expanduser("~/.ssh/{}.pem".format(name))

def ensure_ssh_key(name):
    from paramiko import RSAKey
    ec2 = boto3.resource("ec2")
    for key_pair in ec2.key_pairs.all():
        if key_pair.name == name:
            if not os.path.exists(get_ssh_key_path(name)):
                msg = "Key {} found in EC2, but not in ~/.ssh. Delete the key in EC2, copy it to {}, or specify another key."
                raise KeyError(msg.format(name, get_ssh_key_path(name)))
            break
    else:
        if os.path.exists(get_ssh_key_path(name)):
            ssh_key = RSAKey.from_private_key_file(get_ssh_key_path(name))
        else:
            logger.info("Creating key pair %s", name)
            ssh_key = new_ssh_key()
            ssh_key.write_private_key_file(get_ssh_key_path(name))
        ec2.import_key_pair(KeyName=name,
                            PublicKeyMaterial=get_public_key_from_pair(ssh_key))
        logger.info("Imported SSH key %s", get_ssh_key_path(name))
    return get_ssh_key_path(name)

def hostkey_line(hostnames, key):
    from paramiko import hostkeys
    return hostkeys.HostKeyEntry(hostnames=hostnames, key=key).to_line()

def add_ssh_host_key_to_known_hosts(host_key_line):
    ssh_known_hosts_path = os.path.expanduser("~/.ssh/known_hosts")
    with open(ssh_known_hosts_path, "a") as fh:
        fh.write(host_key_line)
