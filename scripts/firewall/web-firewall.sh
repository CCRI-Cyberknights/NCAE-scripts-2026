#!/bin/bash

# This script will avoid using aliases
# Script must be run as root
if [ "$EUID" -ne 0 ]; then 
  echo "Rquires Root: sudo ./web-firewall.sh"
  exit
fi

# Variables
INTERFACE="en0" # Replace with Interface of server
WEB_SCORING_IP="0.0.0.0" # Replace with WEB scoring IP if found
EXTERNAL_KALI="192.168.24.20" # Replace with IP of any Kali machine used for remote access
DNS_SERVER="172.50.120.20" # Replace with DNS Server IP
DB_SERVER="172.50.120.10" # Replace with DB server IP
INTERNET="0.0.0.0" # Used to access internet for downloading
FLASK_PORT="5000/tcp" # Repalce with Port flask is hosted on
LOOPBACK_IP="127.0.0.1" # Used for Nginx to talk to Flask

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
# WEB Zone
$FIREWALL_CMD --permanent --delete-zone=web_scoring >/dev/null 2>&1
$FIREWALL_CMD --permanent --new-zone=web_scoring
$FIREWALL_CMD --permanent --zone=web_scoring --add-source=${WEB_SCORING_IP}
$FIREWALL_CMD --permanent --zone=web_scoring --add-service=http
$FIREWALL_CMD --permanent --zone=web_scoring --add-service=https
$FIREWALL_CMD --permanent --zone=web_scoring --set-target=ACCEPT

# Loopback Zone
$FIREWALL_CMD --permanent --delete-zone=internal_loop >/dev/null 2>&1
$FIREWALL_CMD --permanent --new-zone=internal_loop
$FIREWALL_CMD --permanent --zone=internal_loop --add-interface=lo
$FIREWALL_CMD --permanent --zone=internal_loop --add-source=${LOOPBACK_IP}
$FIREWALL_CMD --permanent --zone=internal_loop --add-port=${FLASK_PORT}
$FIREWALL_CMD --permanent --zone=internal_loop --set-target=ACCEPT

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
# $FIREWALL_CMD --permanent --zone=icmp --add-source=${WEB_SOCRING_IP}
# $FIREWALL_CMD --permanent --zone=icmp --add-protocol=icmp

# Ignore unknown IPs
# Allow all IPs through scoring services with 0.0.0.0
$FIREWALL_CMD --permanent --zone=drop --add-interface=${INTERFACE}

# Direct rules
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 0 -m state --state INVALID -j DROP
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p udp -d ${DNS_SERVER} --dport 53 -m length --length 0:4096 -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p tcp -d ${DNS_SERVER} --dport 53 -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p tcp -d ${DB_SERVER} --dport 5432 -j ACCEPT
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
