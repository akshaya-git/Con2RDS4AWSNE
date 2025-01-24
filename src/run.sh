# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

#!/bin/sh

echo "Inside Run.sh"

# Assign an IP address to local loopback 
ip addr add 127.0.0.1/32 dev lo
ip link set dev lo up

# Add a hosts record, pointing target site calls to local loopback
echo "127.0.0.1 mstestdb.c23cswqvzlga.us-east-1.rds.amazonaws.com" >> /etc/hosts
echo "127.0.0.2 mstestdb3.c23cswqvzlga.us-east-1.rds.amazonaws.com" >> /etc/hosts
#socat tcp-listen:3306,bind=127.0.0.1 vsock-connect:3:8000 &
echo "Start application"

touch /libnsm.so

# Run traffic forwarder in background and start the server
python3 ./traffic_forwarder.py 127.0.0.1 3306 3 8000 &

echo "Before executing Server app"
python3 ./server.py server 5000
