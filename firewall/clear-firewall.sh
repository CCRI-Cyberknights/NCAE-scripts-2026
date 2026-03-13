#!/bin/bash
# =============================================================================
# clear-firewall.sh
# CCRI Cyberknights — NCAE CyberGames 2026
# =============================================================================
#
# PURPOSE:
#   Reset all standard firewalld zones to a known-clean, locked-down state
#   before applying a custom zone configuration. This script is designed to
#   run immediately before shell-firewall.sh on Rocky Linux VMs.
#
#   It can also be used as an emergency lockdown: if the competition VM is
#   actively compromised and the firewall is in an unknown state, running
#   this script drops all traffic through standard zones immediately.
#
# DESIGN:
#   firewalld ships with several predefined zones (public, external, home,
#   internal, work, trusted). When a competition VM is first accessed, these
#   zones may have services pre-allowed (SSH and DHCPv6 are allowed by default
#   in the public zone) and the interface may be assigned to a permissive zone.
#   This script iterates through all standard zones and:
#     1. Sets the default target to DROP — any packet not matched by an
#        explicit allow rule is silently discarded
#     2. Removes the SSH service allowance — SSH access will be re-added
#        with explicit source restrictions by shell-firewall.sh
#     3. Removes the DHCPv6 client service — IPv6 auto-configuration is not
#        needed in the competition environment
#     4. Removes eth0 from the zone — we reassign the interface to the 'drop'
#        zone explicitly in shell-firewall.sh
#
# USAGE:
#   sudo bash clear-firewall.sh
#   Run this BEFORE shell-firewall.sh. Do not run it on Ubuntu VMs (use UFW).
#
# SUPPORTED OS:
#   Rocky Linux 9 (firewalld)
#   Do NOT run on Ubuntu — Ubuntu uses UFW, not firewalld.
#
# NOTES:
#   --permanent: changes are written to disk and survive firewall-cmd --reload
#                and system reboots. Without --permanent, changes are runtime-only
#                and lost on the next reload.
#   --reload:    applies all pending permanent changes to the live running config.
#                Must be called after all --permanent changes are complete.
#   || true:     not used here because remove-service/remove-interface return
#                non-zero if the service/interface is not present. The loop
#                handles each zone; a missing service in one zone should not
#                abort the whole operation, so error output is suppressed by
#                firewall-cmd itself when the resource doesn't exist.
# =============================================================================

# Iterate over every standard predefined firewalld zone.
# 'trusted' is included because it defaults to ACCEPT and would pass all
# traffic if the interface were ever accidentally assigned to it.
for zone in public external home internal work trusted; do

    # Set the zone's default target to DROP.
    # The target is what happens to packets that do not match any rule in the
    # zone. DROP discards them silently (no ICMP error sent back to sender).
    # ACCEPT (the default for 'trusted') would pass everything — we override that.
    firewall-cmd --permanent --zone=$zone --set-target=DROP

    # Remove the SSH service from this zone.
    # firewalld's predefined 'ssh' service allows TCP port 22. Removing it
    # here ensures no zone accidentally allows SSH after this script runs.
    # shell-firewall.sh will re-add SSH only in the scoring and mgmt-kali zones,
    # with explicit source IP restrictions.
    firewall-cmd --permanent --zone=$zone --remove-service=ssh

    # Remove the DHCPv6 client service from this zone.
    # This service (UDP port 546) is added by default to the public zone on
    # Rocky Linux. The competition environment does not use IPv6, so this
    # is unnecessary attack surface.
    firewall-cmd --permanent --zone=$zone --remove-service=dhcpv6-client

    # Remove eth0 from this zone.
    # Interfaces can only belong to one zone at a time. Removing eth0 here
    # ensures that shell-firewall.sh can assign it to the 'drop' zone cleanly.
    # If eth0 is not in a given zone, firewall-cmd silently ignores the removal.
    firewall-cmd --permanent --zone=$zone --remove-interface=eth0

done

# Apply all permanent changes to the live running configuration.
# Without this line, the changes exist in config files but are not enforced
# until the next system reboot or manual reload. We call it once at the end
# rather than after each zone to minimize unnecessary reloads.
firewall-cmd --reload
