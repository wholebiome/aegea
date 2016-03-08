from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, socket, errno, time

from .printing import GREEN

def wait_for_port(host, port, timeout=600, print_progress=True):
    if print_progress:
        sys.stderr.write("Waiting for {}:{}".format(host, port))
        sys.stderr.flush()
    start_time = time.time()
    while True:
        try:
            socket.socket().connect((host, port))
            if print_progress:
                sys.stderr.write(GREEN("OK") + "\n")
            return
        except Exception:
            time.sleep(1)
            if print_progress:
                sys.stderr.write(".")
                sys.stderr.flush()
            if time.time() - start_time > timeout:
                raise
