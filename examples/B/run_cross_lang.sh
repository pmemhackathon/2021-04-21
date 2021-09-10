#!/bin/bash -ex
#
# shell commands to run this example using multiple language bindings
# alternatively.  All examples use the same engine and can be used
# intertwined to access the same data (in the same kv file).
#

jexec='java -cp ./target/PmemkvExample-1.2.0-jar-with-dependencies.jar PmemkvExample'
my_kvfile=/pmem/kvfile

# remove file if left over from previous run
rm -f $my_kvfile


## add some values using Python
./kv.py $my_kvfile bach 1685-1750
./kv.py $my_kvfile mozart 1756-1791
./kv.py $my_kvfile beethoven 1770-1827


# print some values using Java
cd PmemkvExample
$jexec $my_kvfile bach
$jexec $my_kvfile chopin
cd ..

# add some more values and print all using C++
./pmemkv $my_kvfile brahms 1833-1897
./pmemkv $my_kvfile haydn 1732-1809
./pmemkv $my_kvfile
