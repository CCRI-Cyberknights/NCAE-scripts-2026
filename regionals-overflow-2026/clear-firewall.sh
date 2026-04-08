#!/bin/bash
for zone in public external home internal work trusted; do
    firewall-cmd --permanent --zone=$zone --set-target=DROP
    firewall-cmd --permanent --zone=$zone --remove-service=ssh
    firewall-cmd --permanent --zone=$zone --remove-service=dhcpv6-client
    firewall-cmd --permanent --zone=$zone --remove-interface=eth0
done