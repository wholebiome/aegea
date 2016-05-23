Aegea: Amazon Web Services Operator Interface
=============================================

*Aegea* is a command line interface (CLI) that provides a set of essential commands and terminal dashboards for
operators of Amazon Web Services (AWS) accounts. It is intended to be used in conjunction with the existing
functionality of the `AWS CLI <https://aws.amazon.com/cli/>`_.

Installation
~~~~~~~~~~~~
Run ``pip install .`` in this directory to install Aegea. Before you do this, you will also need to install some system library dependencies:

+--------------+---------+-----------------------------------------------------------------------------------------+
| OS           | Python  | Command                                                                                 |
+==============+=========+=========================================================================================+
| Ubuntu       | Python 2| apt-get install python-dev python-cffi libssl-dev                                       |
+--------------+---------+-----------------------------------------------------------------------------------------+
| Ubuntu       | Python 3| apt-get install python3-dev python3-cffi libssl-dev                                     |
+--------------+---------+-----------------------------------------------------------------------------------------+
| Red Hat      | Python 2| yum install python-devel python-cffi openssl-devel                                      |
+--------------+---------+-----------------------------------------------------------------------------------------+
| Red Hat      | Python 3| yum install python3-devel python3-cffi openssl-devel                                    |
+--------------+---------+-----------------------------------------------------------------------------------------+
| OS X/Homebrew|         | Install Xcode or Xcode Command Line Tools                                               |
+--------------+---------+-----------------------------------------------------------------------------------------+

Configuration management
~~~~~~~~~~~~~~~~~~~~~~~~
Aegea supports ingesting configuration from a configurable array of sources. Each source is a JSON or YAML file.
Configuration sources that follow the first source update the configuration using recursive dictionary merging. Sources are
enumerated in the following order (i.e., in order of increasing priority):

- Site-wide configuration source, ``/etc/NAME/config.(yml|json)``
- User configuration source, ``~/.config/NAME/config.(yml|json)``
- Any sources listed in the colon-delimited variable ``NAME_CONFIG_FILE``
- Command line options

**Array merge operators**: When loading a chain of configuration
 sources, Aegea uses recursive dictionary merging to combine the
 sources. Additionally, when the original config value is a list,
 Aegea supports array manipulation operators, which let you extend and
 modify arrays defined in underlying configurations. See
 https://github.com/kislyuk/tweak#array-merge-operators for a list of
 these operators.

.. image:: https://circleci.com/gh/kislyuk/aegea.svg?style=svg&circle-token=70d22b84025fad5d484ac5f3df1fc0a183c0f516
           :target: https://circleci.com/gh/kislyuk/aegea
