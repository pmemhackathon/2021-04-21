#!/bin/bash -ex
#
# shell commands to run E_recordlog
#

# remove any leftovers from previous runs
rm -f /pmem/E_recordlog

# first run (no pmem file has been created yet)
./scripts/runE

# show the pmem file that was created
ls -l /pmem/E_recordlog

# second run (pmem file exists already)
./scripts/runE
