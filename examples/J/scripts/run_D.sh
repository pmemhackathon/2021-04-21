#!/bin/bash -ex
#
# shell commands to run D_list
#

# remove any leftovers from previous runs
rm -f /pmem/D_list

# first run (no pmem file has been created yet)
./scripts/run workshop.D_list.ListExample

# show the pmem file that was created
ls -l /pmem/D_list

# second run (pmem file exists already)
./scripts/run workshop.D_list.ListExample
