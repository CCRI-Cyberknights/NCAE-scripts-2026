#!/bin/bash


# This script must be run as root
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root: sudo ./admin-create.sh"
   exit 1
fi

# Unlock wheel group
chattr -i /etc/sudoers

# Configuration
NEW_ADMIN="admin"
ADMIN_PASS="changethispassword"

# Create the user
# -m creates the home directory
# -s sets the default shell to bash
useradd -m -s /bin/bash "$NEW_ADMIN"


# Set the password using echo to avoid interactive shell
echo "$NEW_ADMIN:$ADMIN_PASS" | chpasswd

# Add to the wheel group
usermod -aG wheel "$NEW_ADMIN"

# Ensure the wheel group is actually enabled in sudoers
# Uses sed to uncomment the %wheel line in /etc/sudoers
sed -i 's/^# %wheel\tALL=(ALL)\tALL/%wheel\tALL=(ALL)\tALL/' /etc/sudoers

# Lock wheel group
chattr +i /etc/sudoers

# run these commands to confirm creation:
# id admin
# groups admin
# ssh admin@localhost
# cat /etc/sudoers