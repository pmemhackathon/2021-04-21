#!/bin/bash -ex
#
# The shell commands to build the main example.
#

mkdir -p build
cd build
cmake ..
make server
make client
