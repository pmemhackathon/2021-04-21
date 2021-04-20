#!/bin/bash -ex
#
# shell commands to run B_anyintarray
#

# remove any leftovers from previous runs
rm -f /pmem/B_anyintarray

# first run (no pmem file has been created yet)
./scripts/run workshop.B_anyintarray.IntArrayExample

# show the pmem file that was created
ls -l /pmem/B_anyintarray

# second run (pmem file exists already)
./scripts/run workshop.B_anyintarray.IntArrayExample
