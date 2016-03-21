#!/bin/bash -eu

make -C wb.python
wbc.py -d launchWorkers --amiId $(curl http://169.254.169.254/latest/meta-data/ami-id) --instanceAlias worker SOP wb.python/csvs/wb-test.csv
