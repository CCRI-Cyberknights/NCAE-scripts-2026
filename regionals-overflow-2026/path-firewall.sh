#!/bin/bash

# This script will avoid using aliases
# Script must be run as root
if [ "$EUID" -ne 0 ]; then 
  echo "Rquires Root: sudo ./path-firewall.sh"
  exit
fi

# Variables
INTERFACE="enp0s3"
SCORING_IP="192.168.24.22"
EXTERNAL_KALI="192.168.24.20"
DHCP_SERVER="192.168.24.40"
DNS_SERVER="172.50.120.10"
REPO_MIRROR="172.50.100.10"

# Command Paths
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

# stop service to wipe its memory
$SYSTEMCTL stop firewalld

# Wipe red team zones
$RM -rf /etc/firewalld/zones/*
$RM -f /etc/firewalld/direct.xml

# Flush the Kernel memory
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
# Scoring Zone
$FIREWALL_CMD --permanent --delete-zone=scoring >/dev/null 2>&1
$FIREWALL_CMD --permanent --new-zone=scoring
$FIREWALL_CMD --permanent --zone=scoring --add-source=${SCORING_IP}
$FIREWALL_CMD --permanent --zone=scoring --add-service=samba
$FIREWALL_CMD --permanent --zone=scoring --add-service=ssh
$FIREWALL_CMD --permanent --zone=scoring --add-protocol=icmp
$FIREWALL_CMD --permanent --zone=scoring --add-rich-rule='rule service name="ssh" limit value="5/m" accept'
$FIREWALL_CMD --permanent --zone=scoring --set-target=ACCEPT

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

# Ignore unknown IPs unless dhcp
$FIREWALL_CMD --permanent --zone=drop --add-interface=${INTERFACE}
$FIREWALL_CMD --permanent --zone=drop --add-service=dhcp

# Direct rules
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 0 -m state --state INVALID -j DROP
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p udp -d ${DNS_SERVER} --dport 53 -m length --length 0:4096 -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p tcp -d ${DNS_SERVER} --dport 53 -j ACCEPT
$FIREWALL_CMD --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p tcp -d ${REPO_MIRROR} -m multiport --dports 80,443 -j ACCEPT
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
