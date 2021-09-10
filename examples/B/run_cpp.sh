#!/bin/bash -ex
#
# shell commands to run the C++ version of this example
#

my_kvfile=/pmem/kvfile

# remove file if left over from previous run
rm -f $my_kvfile

# add some values
./pmemkv $my_kvfile bach 1685-1750
./pmemkv $my_kvfile mozart 1756-1791

# print a value
./pmemkv $my_kvfile bach

# add some more
./pmemkv $my_kvfile beethoven 1770-1827
./pmemkv $my_kvfile brahms 1833-1897
./pmemkv $my_kvfile haydn 1732-1809

# print all k-v pairs in kvfile
./pmemkv $my_kvfile
