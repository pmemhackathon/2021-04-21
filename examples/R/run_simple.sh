#!/bin/bash -ex
#
# The shell commands to run the simple_* example.
#

SERVER_IP=$RPMA_SOFT_ROCE_IP
SERVER_PORT=$((62000 + $PMEMUSER_ID))

cd build
# usage: ./simple_server <server_address> <port>
./simple_server $SERVER_IP $SERVER_PORT &
sleep 1
# usage: ./simple_client <server_address> <port>
./simple_client $SERVER_IP $SERVER_PORT
