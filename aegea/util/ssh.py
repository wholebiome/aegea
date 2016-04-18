import os, sys
from paramiko import SSHClient
from .. import logger

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
