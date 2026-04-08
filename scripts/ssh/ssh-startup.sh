#!/bin/bash


# This script must be run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root: sudo ./ssh-startup.sh"
   exit 1
fi

# Configuration Variables
CONFIG_SRC="sshd_config"
SSHD_CONFIG_DEST="/etc/ssh/sshd_config"

# Absolute paths to mitigate PATH poisoning or aliased commands
cp_cmd="/usr/bin/cp"
chmod_cmd="/usr/bin/chmod"
chown_cmd="/usr/bin/chown"
systemctl_cmd="/usr/bin/systemctl"
sshd_cmd="/usr/sbin/sshd"

# Verify the hardened configuration file exists in the local directory
if [[ ! -f "$CONFIG_SRC" ]]; then
    echo "Error: Hardened $CONFIG_SRC not found."
    exit 1
fi

# Apply the hardened configuration to the system
$cp_cmd "$CONFIG_SRC" "$SSHD_CONFIG_DEST"

# SSH will refuse to start if the config file is world-writable
# 600 ensures only root can read or write the configuration
$chown_cmd root:root "$SSHD_CONFIG_DEST"
$chmod_cmd 600 "$SSHD_CONFIG_DEST"

# Validate the configuration syntax before attempting a restart
if ! $sshd_cmd -t; then
    echo "SSH configuration test failed! Check /etc/ssh/sshd_config for syntax errors."
    exit 1
fi

# Enable the service to ensure it persists across reboots
# 'enable --now' handles both registration and immediate startup
$systemctl_cmd enable --now sshd

# Restart to ensure the new hardened settings are fully applied to current sessions
$systemctl_cmd restart sshd

echo "SSH service has been hardened and started."
