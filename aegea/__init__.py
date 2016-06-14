"""
Amazon Web Services Operator Interface

For general help, run ``aegea help`` or visit https://github.com/kislyuk/aegea/wiki.
For help with individual commands, run ``aegea <command> --help``.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, logging, shutil, json
from textwrap import fill
from tweak import Config

try:
    import pkg_resources
    __version__ = pkg_resources.get_distribution(__name__).version
except Exception:
    __version__ = "0.0.0"

logger = logging.getLogger(__name__)

config, parser, subparsers = None, None, None

def initialize():
    global config, parser, subparsers
    from .util.printing import BOLD, RED, ENDC
    config = Config(__name__, use_yaml=True, save_on_exit=False)
    if not os.path.exists(config.config_files[1]):
        config.save()
        shutil.copy(os.path.join(os.path.dirname(__file__), "default_config.yml"), config.config_files[1])
        logger.info("Wrote new config file %s with default values", config.config_files[1])
        config = Config(__name__, use_yaml=True, save_on_exit=False)

    parser = argparse.ArgumentParser(
        description="{}: {}".format(BOLD() + RED() + __name__.capitalize() + ENDC(), fill(__doc__.strip())),
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--version", action="version", version='%(prog)s {version}'.format(version=__version__))
    subparsers = parser.add_subparsers(title='commands')
    subparsers.add_parser("help").set_defaults(entry_point=lambda args: parser.print_help())

def main(args=None):
    parsed_args = parser.parse_args(args=args)
    has_attrs = (getattr(parsed_args, "sort_by", None) and
                 getattr(parsed_args, "columns", None))
    if has_attrs and parsed_args.sort_by not in parsed_args.columns:
        parsed_args.columns.append(parsed_args.sort_by)
    result = parsed_args.entry_point(parsed_args)
    if result is not None:
        print(json.dumps(result))

def register_parser(function, **kwargs):
    if config is None:
        initialize()
    parser = subparsers.add_parser(function.__name__, **kwargs)
    parser.add_argument("--max-col-width", "-w", type=int, default=32)
    parser.add_argument("--json", action="store_true", help="Output tabular data as a JSON-formatted list of objects")
    parser.add_argument("--log-level", type=logger.setLevel,
                        help=str([logging.getLevelName(i) for i in range(0, 60, 10)]),
                        default=config.get("log_level"))
    parser.set_defaults(entry_point=function)
    parser.set_defaults(**config.get(function.__name__, {}))
    if parser.description is None:
        parser.description = kwargs.get("help")
    return parser
