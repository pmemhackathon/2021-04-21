#!/bin/bash -ex
#
# shell commands to run the Python version of this example
#

my_kvfile=/pmem/kvfile

# remove file if left over from previous run
rm -f $my_kvfile

# add some values
./kv.py $my_kvfile bach 1685-1750
./kv.py $my_kvfile mozart 1756-1791

# print a value
./kv.py $my_kvfile bach
# print a non-existent value
./kv.py $my_kvfile chopin

# add some more
./kv.py $my_kvfile beethoven 1770-1827
./kv.py $my_kvfile brahms 1833-1897
./kv.py $my_kvfile haydn 1732-1809

# print all k-v pairs in kvfile
./kv.py $my_kvfile
