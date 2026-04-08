#!/bin/bash


# Script must be run as Root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root: sudo ./user-lockdown.sh"
   exit 1
fi

# Configuration
SCORING_USERS="scoring_users.txt" # One account per line in file
BACKUP_DIR="/root/user_backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Ensure scoring_users file exists
if [[ ! -f "$SCORING_USERS" ]]; then
    echo "Error: scoring_users file '$SCORING_USERS' not found."
    exit 1
fi

# Unlock passwd and shadow
chattr -i /etc/passwd /etc/shadow

# Create backup repository for ssh keys
mkdir -p "$BACKUP_DIR"

# Get all "real" users (UID >= 1000) and exclude those in the scoring_users
# Maps a file line by line into an array
# User nobody is a Rocky user
# TARGET_USERS is an array of all users
mapfile -t TARGET_USERS < <(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | grep -vxf "$SCORING_USERS") 

for USER in "${TARGET_USERS[@]}"; do
    # Move SSH keys and Cronjobs to repository
    USER_BACKUP="$BACKUP_DIR/${USER}_$DATE"
    mkdir -p "$USER_BACKUP"
    
    # Move SSH keys if they exist
    HOME_DIR=$(getent passwd "$USER" | cut -d: -f6) # Gets the user entry from the administrative database sets ":" as the delimiter and gets the 6th field which is the users home directory
    if [[ -d "$HOME_DIR/.ssh" ]]; then
        mv "$HOME_DIR/.ssh" "$USER_BACKUP/ssh_keys"
    fi

    # Move Cronjobs if they exist
    if [[ -f "/var/spool/cron/$USER" ]]; then
        mv "/var/spool/cron/$USER" "$USER_BACKUP/cronjob"
    fi

    # Terminate active sessions
    pkill -u "$USER" -9

    # Change shell to /sbin/nologin, lock the account, and set home directory to /dev/null
    usermod -s /sbin/nologin -L -d /dev/null "$USER"

    # Set account to expire immediately
    chage -E 0 "$USER"

done

chattr +i /etc/passwd /etc/shadow

echo "Lockdown complete. Backups located in $BACKUP_DIR"
