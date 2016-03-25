"""
Amazon Web Services Operator Interface
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, logging, shutil

from tweak import Config

from .util.printing import BOLD, RED, ENDC

try:
    import pkg_resources
    __version__ = pkg_resources.require(__name__)[0].version
except Exception:
    __version__ = "UNKNOWN_VERSION"

logger = logging.getLogger(__name__)

config = Config(__name__, use_yaml=True, save_on_exit=False)
if not os.path.exists(config._config_file):
    config.save()
    shutil.copy(os.path.join(os.path.dirname(__file__), "default_config.yml"), config._config_file)
    logger.info("Wrote new config file %s with default values", config._config_file)
    config = Config(__name__, use_yaml=True, save_on_exit=False)

parser = argparse.ArgumentParser(description="{}: {}".format(BOLD() + RED() + __name__.capitalize() + ENDC(), __doc__))
parser.add_argument("--version", action="version", version='%(prog)s {version}'.format(version=__version__))
subparsers = parser.add_subparsers(title='commands')

def register_parser(function, **kwargs):
    parser = subparsers.add_parser(function.__name__, **kwargs)
    parser.add_argument("--max-col-width", "-w", type=int, default=32)
    parser.set_defaults(entry_point=function)
    parser.set_defaults(**config.get(function.__name__, {}))
    if parser.description is None:
        parser.description = kwargs.get("help")
    return parser
