#!/bin/bash

# Get a list of currently logged in users
current_users=$(who | awk '{print $1}') >> /var/log/knownusers.log
rm -f user_setup.sh
