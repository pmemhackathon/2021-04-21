#!/bin/bash -ex
#
# The shell commands to run the rping test.
#

SERVER_IP=$RPMA_SOFT_ROCE_IP

rping -s -a $SERVER_IP -C 10 &
sleep 1
rping -c -a $SERVER_IP -C 10 -v
