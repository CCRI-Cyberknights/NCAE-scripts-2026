#!/bin/bash

# This script will avoid using aliases
# Script must be run as root
if [ "$EUID" -ne 0 ]; then 
  echo "Rquires Root: sudo ./dns-firewall.sh"
  exit
fi

# Variables
# Replace text in quotes with string
INTERFACE="en0" # Replace with interface of server
DNS_SCORING_IP="0.0.0.0" # Replace with DNS scoring IP if found
EXTERNAL_KALI="192.168.24.20" # Replace with IP of any Kali machine used for remote access
INTERNET="0.0.0.0" # Used to access the internet for downloading
PUBLIC_DNS="8.8.8.8" # Google DNS server

# Path to command binaries
# Still confirm the itegrity of these binaries and verify with "which" command
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
# DNS Zone
$FIREWALL_CMD --permanent --delete-zone=dns_scoring >/dev/null 2>&1
$FIREWALL_CMD --permanent --new-zone=dns_scoring
$FIREWALL_CMD --permanent --zone=dns_scoring --add-source=${DNS_SCORING_IP}
$FIREWALL_CMD --permanent --zone=dns_scoring --add-service=dns
$FIREWALL_CMD --permanent --zone=dns_scoring --set-target=ACCEPT

# Team Kali
$FIREWALL_CMD --permanent --delete-zone=mgmt-kali >/dev/null 2>&1
$FIREWALL_CMD --permanent --new-zone=mgmt-kali
$FIREWALL_CMD --permanent --zone=mgmt-kali --add-source=${EXTERNAL_KALI}
$FIREWALL_CMD --permanent --zone=mgmt-kali --add-service=ssh
$FIREWALL_CMD --permanent --zone=mgmt-kali --add-protocol=icmp
$FIREWALL_CMD --permanent --zone=mgmt-kali --set-target=ACCEPT

# Add rule for ICMP if scoring IP needs to ping services
# $FIREWALL_CMD --permanent --delete-zone=icmp >/dev/null 2>&1
# $FIREWALL_CMD --permanent --new-zone=icmp
# $FIREWALL_CMD --permanent --zone=icmp --add-source=${DNS_SOCRING_IP}
# $FIREWALL_CMD --permanent --zone=icmp --add-protocol=icmp

# Ignore unknown IPs that are not needed
# Allow all IPs through scoring services with 0.0.0.0
$FIREWALL_CMD --permanent --zone=drop --add-interface=${INTERFACE}

# Direct rules
# Set otubound dns to 0.0.0.0 or INTERNET if server needs more than google dns
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 0 -m state --state INVALID -j DROP
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p udp -d ${PUBLIC_DNS} --dport 53 -m length --length 0:4096 -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p tcp -d ${PUBLIC_DNS} --dport 53 -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p tcp -d ${INTERNET} -m multiport --dports 80,443 -j ACCEPT
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
