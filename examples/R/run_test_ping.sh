#!/bin/bash -ex
#
# The shell commands to run the basic ping test.
#

SERVER_IP=$RPMA_SOFT_ROCE_IP

ping -c5 $SERVER_IP
