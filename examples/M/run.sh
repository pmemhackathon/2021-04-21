#!/bin/bash -ex
#
# shell commands to run this example
#

# run the example program on pmem, first write the data to the file
./RAS write /pmem/rawfile "This is new data written to the file"
# read the data from the file
./RAS read /pmem/rawfile
