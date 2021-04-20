#!/bin/bash -ex
#
# shell commands to run C_genericarray
#

# remove any leftovers from previous runs
rm -f /pmem/C_genericarray

# first run (no pmem file has been created yet)
./scripts/run workshop.C_genericarray.ArrayExample

# show the pmem file that was created
ls -l /pmem/C_genericarray

# second run (pmem file exists already)
./scripts/run workshop.C_genericarray.ArrayExample
