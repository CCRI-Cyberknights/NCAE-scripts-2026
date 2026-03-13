#!/bin/bash
INTERFACE="enp0s3"
SCORING_IP="192.168.24.22"
EXTERNAL_KALI="192.168.24.20"
DHCP_SERVER="192.168.24.40"
DNS_SERVER="172.50.120.10"
REPO_MIRROR="172.50.100.10"

#Scoring Zone
firewall-cmd --permanent --new-zone=scoring
firewall-cmd --permanent --zone=scoring --add-source=${SCORING_IP}
firewall-cmd --permanent --zone=scoring --add-service=samba
firewall-cmd --permanent --zone=scoring --add-service=ssh
firewall-cmd --permanent --zone=scoring --add-protocol=icmp
firewall-cmd --permanent --zone=scoring --add-rich-rule='rule service name="ssh" limit value="5/m" accept'
firewall-cmd --permanent --zone=scoring --set-target=ACCEPT

#Team Kali
firewall-cmd --permanent --new-zone=mgmt-kali
firewall-cmd --permanent --zone=mgmt-kali --add-source=${EXTERNAL_KALI}
firewall-cmd --permanent --zone=mgmt-kali --add-service=ssh
firewall-cmd --permanent --zone=mgmt-kali --add-protocol=icmp
firewall-cmd --permanent --zone=mgmt-kali --set-target=ACCEPT

#DHCP Server
firewall-cmd --permanent --new-zone=dhcp-trust
firewall-cmd --permanent --zone=dhcp-trust --add-source=${DHCP_SERVER}
firewall-cmd --permanent --zone=dhcp-trust --add-service=dhcp
firewall-cmd --permanent --zone=dhcp-trust --set-target=ACCEPT

#Ignore unknown IPs unless dhcp
firewall-cmd --permanent --zone=drop --add-interface=${INTERFACE}
firewall-cmd --permanent --zone=drop --add-service=dhcp
#comment dhcp once the IP is known

#OUTBOUND rules
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -m state --state INVALID -j DROP
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p udp -d ${DNS_SERVER} --dport 53 -m length --length 0:512 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p tcp -d ${DNS_SERVER} --dport 53 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p tcp -d ${REPO_MIRROR} -m multiport --dports 80,443 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p udp --dport 67:68 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 254 -j LOG --log-prefix "REVERSE_SHELL_ATTEMPT: "
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 255 -j DROP

#Reload to use this configuration
firewall-cmd --reload
