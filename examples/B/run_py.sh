#!/bin/bash -ex
#
# shell commands to run the C++ version of this example
#

# remove file if left over from previous run
rm -f /pmem/kvfile

# add some values
./kv.py /pmem/kvfile bach 1685-1750
./kv.py /pmem/kvfile mozart 1756-1791

# print a value
./kv.py /pmem/kvfile bach

# add some more
./kv.py /pmem/kvfile beethoven 1770-1827
./kv.py /pmem/kvfile brahms 1833-1897
./kv.py /pmem/kvfile haydn 1732-1809

# print all k-v pairs in kvfile
./kv.py /pmem/kvfile
