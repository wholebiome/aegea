"""
Amazon Web Services Operator Interface
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, logging, shutil
from tweak import Config

try:
    import pkg_resources
    __version__ = pkg_resources.require(__name__)[0].version
except Exception:
    __version__ = "UNKNOWN_VERSION"

logger = logging.getLogger(__name__)

config, parser, subparsers = None, None, None

def initialize():
    global config, parser, subparsers
    from .util.printing import BOLD, RED, ENDC
    config = Config(__name__, use_yaml=True, save_on_exit=False)
    if not os.path.exists(config._config_files[1]):
        config.save()
        shutil.copy(os.path.join(os.path.dirname(__file__), "default_config.yml"), config._config_files[1])
        logger.info("Wrote new config file %s with default values", config._config_files[1])
        config = Config(__name__, use_yaml=True, save_on_exit=False)

    parser = argparse.ArgumentParser(description="{}: {}".format(BOLD() + RED() + __name__.capitalize() + ENDC(), __doc__))
    parser.add_argument("--version", action="version", version='%(prog)s {version}'.format(version=__version__))
    subparsers = parser.add_subparsers(title='commands')

def register_parser(function, **kwargs):
    if config is None:
        initialize()
    parser = subparsers.add_parser(function.__name__, **kwargs)
    parser.add_argument("--max-col-width", "-w", type=int, default=32)
    parser.add_argument("--log-level", type=logging.getLogger().setLevel, help=str([logging.getLevelName(i) for i in range(0, 60, 10)]), default=config.get("log_level"))
    parser.set_defaults(entry_point=function)
    parser.set_defaults(**config.get(function.__name__, {}))
    if parser.description is None:
        parser.description = kwargs.get("help")
    return parser
