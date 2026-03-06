#!/bin/bash

knowconn=$(ss -tunap | awk '{print$7}' | grep -Eo "pid=[0-9]{1,}")
echo "$knowconn" >> /var/log/connections.log
rm -f piddetect.sh
