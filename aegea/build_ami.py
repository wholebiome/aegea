from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json, time, datetime

import boto3
from paramiko import SSHClient, SFTPClient, RSAKey, SSHException

from . import register_parser, logger
from .util import wait_net_service
from .util.aws import locate_ubuntu_ami, get_user_data, ensure_vpc, ensure_subnet, ensure_ingress_rule, ensure_security_group, set_tags
from .util.crypto import ensure_ssh_key, new_ssh_key, add_ssh_host_key_to_known_hosts

class AegeaSSHClient(SSHClient):
    def check_call(self, *args, **kwargs):
        sys.stdout.write(self.check_output(*args, **kwargs))

    def check_output(self, command, input_data=None):
        logger.info('Running "%s"', command)
        stdin, stdout, stderr = self.exec_command(command)
        if input_data is not None:
            stdin.write(input_data)
        exit_code = stdout.channel.recv_exit_status()
        sys.stderr.write(stderr.read().decode("utf-8"))
        if exit_code != os.EX_OK:
            raise Exception('Error while running "{}": {}'.format(command, os.errno.errorcode.get(exit_code)))
        return stdout.read().decode("utf-8")

def get_bootstrap_files():
    manifest = []
    rootfs_skel_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "worker", "rootfs")
    for root, dirs, files in os.walk(rootfs_skel_dir):
        for file_ in files:
            with open(os.path.join(root, file_)) as fh:
                manifest.append(dict(path=os.path.join("/", os.path.relpath(root, rootfs_skel_dir), file_),
                                     content=fh.read()))
    return manifest

def get_bootstrap_commands():
    return ["apt-get remove --yes popularity-contest postfix",
            "update-grub",
            "grub-install /dev/xvda",
            "pip3 install keymaker",
            "keymaker install",
            "apt-get clean"]

def get_bootstrap_packages():
    return ["iptables-persistent", "docker.io", "debian-goodies", "bridge-utils", "squid-deb-proxy", "pixz",
            "cryptsetup-bin", "mdadm", "btrfs-tools", "libffi-dev", "libssl-dev", "libxml2-dev", "libxslt1-dev", "htop",
            "pydf", "jq", "httpie", "python3-pip", "nfs-common", "fail2ban", "awscli"]

def build_image(args):
    ec2 = boto3.resource("ec2")
    iam = boto3.resource("iam")
    ensure_ssh_key(args.ssh_key_name)
    if args.snapshot_existing_host:
        instance = ec2.Instance(args.snapshot_existing_host)
        init_ami = "Unknown"
    else:
        init_ami = locate_ubuntu_ami(region="us-west-2")
        vpc = ensure_vpc()
        subnet = ensure_subnet(vpc)
        security_group = ensure_security_group("test", vpc)
        instance_type = "t2.micro"
        ssh_host_key = new_ssh_key()
        instances = subnet.create_instances(ImageId=init_ami,
                                            KeyName=args.ssh_key_name,
                                            SecurityGroupIds=[security_group.id],
                                            InstanceType=instance_type,
                                            #Placement={"Tenancy": config["aws"]["instance_placement_tenancy"]},
                                            #IamInstanceProfile=dict(Arn=instance_profile.arn),
                                            UserData=get_user_data(host_key=ssh_host_key,
                                                                   commands=get_bootstrap_commands(),
                                                                   packages=get_bootstrap_packages(),
                                                                   files=get_bootstrap_files()),
                                            MinCount=1,
                                            MaxCount=1)
        instance = instances[0]
        instance.wait_until_running()
        logger.info("Launched %s in %s", instance, subnet)
        add_ssh_host_key_to_known_hosts(instance.public_dns_name, ssh_host_key)
        set_tags(instance, Name="{}.{}".format(__name__, datetime.datetime.now().isoformat()))

    ssh_client = AegeaSSHClient()
    ssh_client.load_system_host_keys()
    wait_net_service(instance.public_dns_name, 22)
    ssh_client.connect(instance.public_dns_name,
                       username="ubuntu",
                       key_filename=os.path.join(os.path.expanduser("~/.ssh"), args.ssh_key_name + ".pem"))
    while True:
        try:
            if ssh_client.check_output("sudo jq .v1.errors /var/lib/cloud/data/result.json").strip() != "[]":
                raise Exception("cloud-init encountered errors")
            break
        except Exception as e:
            if "ENOENT" in str(e):
                time.sleep(1)
            else:
                raise

    image = instance.create_image(Name=args.name, Description="Built by {} for {}, base={}".format(__name__, iam.CurrentUser().user.name, init_ami))
    print(image.id)
    if args.wait_for_ami:
        ec2.meta.client.get_waiter('image_available').wait(ImageIds=[image.id])

parser = register_parser(build_image, help='Build an EC2 AMI')
parser.add_argument("name", default="test")
parser.add_argument("--snapshot-existing-host", type=str)
parser.add_argument("--wait-for-ami", action="store_true")
parser.add_argument("--ssh-key-name", default=__name__)
