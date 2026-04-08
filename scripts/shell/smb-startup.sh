#!/bin/bash


# Ensure the script is run with root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

# Configuration Variables
SHARE_PATH="/srv/samba/share"
CONFIG_SRC="smb.conf"
USER_LIST="samba_users.txt"
SAFE_VERSION="4.18.0" # Example threshold for Rocky 9 security standards
DEFAULT_PASS="changethispassword"

# Absoulte paths to commands
# Confirm path with "which" and "command -v" commands and check integrity
rpm="/usr/bin/rpm"
sort="/usr/bin/sort"
dnf="/usr/bin/dnf"
cp="/usr/bin/cp"
mkdir="/usr/bin/mkdir"
chmod="/usr/bin/chmod"
chown="/usr/bin/chown"
systemctl="/usr/bin/systemctl"
id="/usr/bin/id"
smbpasswd="/usr/bin/smbpasswd"

# Function to compare versions
version_test() { printf '%s\n%s' "$1" "$2" | $sort -C -V; }

# Check for Samba installation and verify version safety
if $rpm -q samba &> /dev/null; then
    CURRENT_VER=$($rpm -q --queryformat '%{VERSION}' samba)
    
    if version_test "$SAFE_VERSION" "$CURRENT_VER"; then
        echo "Samba $CURRENT_VER is installed and meets version requirements."
    else
        echo "Samba version $CURRENT_VER is outdated. Updating..."
        $dnf update -y samba
    fi
else
    echo "Samba not found. Installing latest version..."
    $dnf install -y samba samba-client samba-common
fi

# Deploy the configuration file
if [[ -f "$CONFIG_SRC" ]]; then
    $cp "$CONFIG_SRC" /etc/samba/smb.conf
else
    echo "Error: $CONFIG_SRC not found in current directory."
    exit 1
fi

# Prepare the filesystem for the share
$mkdir -p "$SHARE_PATH"
$chmod -R 0755 "$SHARE_PATH"
$chown -R nobody:nobody "$SHARE_PATH"

# Configure SELinux to allow Samba to serve the directory
if /usr/sbin/getsebool samba_export_all_rw &> /dev/null; then
    echo "Applying SELinux boolean for Samba"
    /usr/sbin/setsebool -P samba_export_all_rw on
else
    echo "Boolean failed to set, appyling manual context"
    /usr/bin/chcon -R -t samba_share_t "$SHARE_PATH"
fi

# Enable and start services to verify baseline functionality
$systemctl enable --now smb nmb

# Check service status before proceeding
if ! $systemctl is-active --quiet smb; then
    echo "Samba failed to start. Check /etc/samba/smb.conf for errors."
    exit 1
fi

# Add users from the text file to the Samba database
# This assumes users already exist in /etc/passwd
if [[ -f "$USER_LIST" ]]; then
    while IFS=":" read -r username password; do
        if $id "$username" &>/dev/null; then
            (echo "$password"; echo "$password") | $smbpasswd -s -a "$username"
        fi
    done < "$USER_LIST"
else
    echo "Error: $USER_LIST not found."
fi

# Configure firewall to allow Samba traffic
firewall-cmd --permanent --add-service=samba
firewall-cmd --reload

# Restart service to apply all user and configuration changes
$systemctl restart smb
echo "Samba setup complete."
