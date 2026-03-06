#!/bin/bash
# Get a list of currently logged in users
current_users=$(who | awk '{print $1}')

# Loop through each in current_users list
while read username; do
    # Check if the username is known
    if ! echo $(</var/log/knownusers.log) | grep -q "$username"; then
        msg="INTRUDER DETECTED!!!            ${username}                     INTRUDER DETECTED!!!"
        time=$(date "+%H:%M:%S")
        # Echo the message to all users and save the log
        echo "$msg" | wall
        echo "${time} [INTRUDER ALERT]    ${username} SPOTTED AND IS A BAD USER">> /var/log/detectlog.log
    fi
done <<< "$current_users"
