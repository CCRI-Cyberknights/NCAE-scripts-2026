#!/bin/bash

# This script will avoid using aliases
# Script must be run as root
if [ "$EUID" -ne 0 ]; then 
  echo "Rquires Root: sudo ./shell-firewall.sh"
  exit
fi

# Variables
INTERFACE="en0" # Replace with Interface of server
SSH_SCORING_IP="0.0.0.0" # Replace with SSH scoring IP if found
SMB_SCORING_IP="0.0.0.0" # Replace with SMB socring IP if found
EXTERNAL_KALI="192.168.24.20" # Replace with IP of any Kali machine used for remote access
DHCP_SERVER="0.0.0.0" # Replace with DHCP Server IP if found
DNS_SERVER="172.50.120.10" # Replace with DNS Server IP
INTERNET="172.50.100.10" # Used to access internet for downloading

# Path to command binaries
# Still confirm the itegrity of these binaries
# Verify with "which" command
CHATTR="/usr/bin/chattr"
SYSTEMCTL="/usr/bin/systemctl"
RM="/usr/bin/rm"
IPTABLES="/usr/sbin/iptables"
NFT="/usr/sbin/nft"
FIREWALL_CMD="/usr/bin/firewall-cmd"

# Remove immutable flags to unlock files needed
$CHATTR -i /etc/firewalld/direct.xml
$CHATTR -R -i /etc/firewalld/zones/
$CHATTR -i /usr/sbin/xtables-nft-multi
$CHATTR -i /usr/sbin/firewalld
$CHATTR -i /usr/sbin/nft

# Stop service to wipe rules and zones
$SYSTEMCTL stop firewalld

# Wipe all current zones used by firewalld
$RM -rf /etc/firewalld/zones/*
$RM -f /etc/firewalld/direct.xml

# Flush the Kernel memory
# Removes all current rules
$IPTABLES -P INPUT ACCEPT
$IPTABLES -P FORWARD ACCEPT
$IPTABLES -P OUTPUT ACCEPT
$IPTABLES -t nat -F
$IPTABLES -t mangle -F
$IPTABLES -F
$IPTABLES -X
$NFT flush ruleset

# Firewalld will be in default state
$SYSTEMCTL start firewalld

# Create Custom firewall zones
# SMB Zone
$FIREWALL_CMD --permanent --delete-zone=samba >/dev/null 2>&1
$FIREWALL_CMD --permanent --new-zone=samba
$FIREWALL_CMD --permanent --zone=samba --add-source=${SMB_SCORING_IP}
$FIREWALL_CMD --permanent --zone=samba --add-service=samba
$FIREWALL_CMD --permanent --zone=samba --set-target=ACCEPT

# SSH Zone
$FIREWALL_CMD --permanent --delete-zone=ssh >/dev/null 2>&1
$FIREWALL_CMD --permanent --new-zone=ssh
$FIREWALL_CMD --permanent --zone=ssh --add-source=${SSH_SCORING_IP}
$FIREWALL_CMD --permanent --zone=ssh --add-service=ssh
$FIREWALL_CMD --permanent --zone=ssh --add-rich-rule='rule service name="ssh" limit value="5/m" accept'
$FIREWALL_CMD --permanent --zone=ssh --set-target=ACCEPT

# Team Kali
$FIREWALL_CMD --permanent --delete-zone=mgmt-kali >/dev/null 2>&1
$FIREWALL_CMD --permanent --new-zone=mgmt-kali
$FIREWALL_CMD --permanent --zone=mgmt-kali --add-source=${EXTERNAL_KALI}
$FIREWALL_CMD --permanent --zone=mgmt-kali --add-service=ssh
$FIREWALL_CMD --permanent --zone=mgmt-kali --add-protocol=icmp
$FIREWALL_CMD --permanent --zone=mgmt-kali --set-target=ACCEPT

# DHCP Server
$FIREWALL_CMD --permanent --delete-zone=dhcp-trust >/dev/null 2>&1
$FIREWALL_CMD --permanent --new-zone=dhcp-trust
$FIREWALL_CMD --permanent --zone=dhcp-trust --add-source=${DHCP_SERVER}
$FIREWALL_CMD --permanent --zone=dhcp-trust --add-service=dhcp
$FIREWALL_CMD --permanent --zone=dhcp-trust --set-target=ACCEPT

# Add rule for ICMP if scoring IP needs to ping services
# $FIREWALL_CMD --permanent --delete-zone=icmp >/dev/null 2>&1
# $FIREWALL_CMD --permanent --new-zone=icmp
# $FIREWALL_CMD --permanent --zone=icmp --add-source=${SMB_SOCRING_IP}
# $FIREWALL_CMD --permanent --zone=icmp --add-source=${SSH_SOCRING_IP}
# $FIREWALL_CMD --permanent --zone=icmp --add-protocol=icmp

# Ignore unknown IPs unless dhcp
# Allow all IPs through scoring services with 0.0.0.0
$FIREWALL_CMD --permanent --zone=drop --add-interface=${INTERFACE}
$FIREWALL_CMD --permanent --zone=drop --add-service=dhcp

# Direct rules
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 0 -m state --state INVALID -j DROP
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p udp -d ${DNS_SERVER} --dport 53 -m length --length 0:4096 -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p tcp -d ${DNS_SERVER} --dport 53 -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p tcp -d ${INTERNET} -m multiport --dports 80,443 -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p udp --dport 67:68 -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 254 -j LOG --log-prefix "REVERSE_SHELL_ATTEMPT: "
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 255 -j DROP

# Reload to use this configuration
$FIREWALL_CMD --reload

# Lock the firewall configs and files
$CHATTR +i /etc/firewalld/direct.xml
$CHATTR -R +i /etc/firewalld/zones/
$CHATTR +i /usr/sbin/xtables-nft-multi
$CHATTR +i /usr/sbin/firewalld
$CHATTR +i /usr/sbin/nft
