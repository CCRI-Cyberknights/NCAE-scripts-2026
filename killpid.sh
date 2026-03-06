#!/bin/bash

currconn=$(ss -tunap | awk '{print$7}' | grep -Eo "pid=[0-9]{1,}")

while read conn; do
    if ! echo $(</var/log/connections.log) | grep -q "$conn"; then
        msg="New Connection Detected, attempting to kill"
        pid=${conn:4}
        $(kill -9 "$pid")
    fi
done <<< "$currconn"
