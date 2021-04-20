#!/bin/bash -ex
#
# shell commands to run A_intarray
#

# remove any leftovers from previous runs
rm -f /pmem/A_intarray

# first run (no pmem file has been created yet)
./scripts/run workshop.A_intarray.IntArrayExample

# show the pmem file that was created
ls -l /pmem/A_intarray

# second run (pmem file exists already)
./scripts/run workshop.A_intarray.IntArrayExample
