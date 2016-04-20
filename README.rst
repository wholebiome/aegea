Aegea: Amazon Web Services Operator Interface
=============================================

*Aegea* is a command line interface (CLI) that provides a set of essential commands and terminal dashboards for
operators of Amazon Web Services (AWS) accounts. It is intended to be used in conjunction with the existing
functionality of the `AWS CLI <https://aws.amazon.com/cli/>`_.

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
