#!/bin/bash -ex
#
# shell commands to run the Java version of this example
#

cd PmemkvExample
jexec='java -cp ./target/PmemkvExample-1.2.0-jar-with-dependencies.jar PmemkvExample'
my_kvfile=/pmem/kvfile

# remove file if left over from previous run
rm -f $my_kvfile

# add some values
$jexec $my_kvfile bach 1685-1750
$jexec $my_kvfile mozart 1756-1791

# print a value
$jexec $my_kvfile bach
# print a non-existent value
$jexec $my_kvfile chopin

# add some more
$jexec $my_kvfile beethoven 1770-1827
$jexec $my_kvfile brahms 1833-1897
$jexec $my_kvfile haydn 1732-1809

# print all k-v pairs in kvfile
$jexec $my_kvfile

cd ..
