#!/bin/bash

SAFE_USERS="root admin_user scoring_user"
# Look for users with ACTIVE shells (not nologin/false)
for entry in $(/usr/bin/grep -E "/bin/bash|/bin/sh" /etc/passwd); do
    user=$(echo $entry | cut -d: -f1)
    current_shell=$(echo $entry | cut -d: -f7)

    # If user is not in SAFE_USERS list set them to nologin shell
    if [[ ! $SAFE_USERS =~ (^|[[:space:]])"$user"($|[[:space:]]) ]]; then
        echo "[!] Locking unauthorized user: $user (was $current_shell)"
        /usr/sbin/usermod -s /sbin/nologin "$user"
    else
        echo "[+] Leaving $user with their original shell: $current_shell"
    fi
done
