#!/bin/bash
# =============================================================================
# shell-firewall.sh
# CCRI Cyberknights — NCAE CyberGames 2026
# =============================================================================
#
# PURPOSE:
#   Configure firewalld zones for the shell VM (Rocky Linux 9) with a
#   whitelist-only inbound policy and a tightly restricted outbound policy
#   designed to prevent reverse shell callbacks to the red team.
#
# DESIGN:
#   firewalld uses a zone-based model: each network interface is assigned to
#   a zone, and each zone has its own set of allowed services and a default
#   target (ACCEPT or DROP). This script creates three custom zones:
#
#   scoring    — allows the scoring engine to connect in for SSH and SMB checks.
#                Source is restricted to the scoring engine's IP so only that
#                host can use the allowed services.
#
#   mgmt-kali  — allows our team's Kali workstation to SSH in for management.
#                Source is restricted to our Kali IP; all other SSH attempts
#                are dropped at the interface level before reaching sshd.
#
#   dhcp-trust — allows DHCP traffic from the known DHCP server so the VM
#                can acquire or renew its IP address during the competition.
#
#   The physical interface (detected automatically) is assigned to the built-in
#   'drop' zone, which drops all traffic not matched by the custom zones above.
#   This implements a default-deny posture: anything not explicitly allowed is
#   silently discarded.
#
#   Outbound rules use firewalld's 'direct' interface (raw iptables rules in
#   the OUTPUT chain) because firewalld's zone model only governs inbound
#   traffic. The outbound rules:
#     - Drop INVALID state packets (malformed, out-of-sequence)
#     - Allow ESTABLISHED/RELATED traffic (responses to our own connections)
#     - Allow DNS queries to our dns VM only (UDP <=512 bytes / TCP)
#     - Allow HTTP/HTTPS to the repo mirror (for package installs if needed)
#     - Allow DHCP (UDP 67-68) for lease renewal
#     - LOG any other outbound packet with the prefix "REVERSE_SHELL_ATTEMPT:"
#     - DROP all remaining outbound traffic (default deny egress)
#
#   The LOG rule before the final DROP is the key defensive feature: if the red
#   team establishes a reverse shell and it tries to phone home, the outbound
#   packet is both logged (visible in journalctl) and dropped.
#
# HARDCODED VALUES:
#   None. All five environment-specific IPs are prompted at runtime via ask_ip().
#   The original version of this script had hardcoded IPs from the practice
#   environment, which would have been wrong in the actual competition network.
#   Prompting at runtime ensures the script works regardless of which team
#   number or subnet we are assigned.
#
# USAGE:
#   sudo bash shell-firewall.sh
#   Run clear-firewall.sh first to start from a clean state.
#   Run on Rocky Linux VMs only (shell, dns). Ubuntu VMs use UFW.
#
# DEPENDENCIES:
#   firewalld (active and running)
#   ip (iproute2) — for default route interface detection
# =============================================================================

# Enforce root: firewall-cmd requires elevated privileges
[[ "$EUID" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

# =============================================================================
# ask_ip — interactively prompt for an IPv4 address with validation
# =============================================================================
# We need five IP addresses that vary by competition environment (team number,
# network segment). Rather than hardcoding them, we prompt the operator at
# runtime and re-prompt until a valid address is entered.
#
# Validation uses a regex: four groups of 1-3 digits separated by dots.
# This catches obvious typos (wrong digit count, missing octets) before the
# address is passed to firewall-cmd, where a malformed IP would silently fail
# or produce an incorrect rule.
ask_ip() {
    local prompt="$1" var
    while true; do
        read -r -p "$prompt: " var

        # Check the pattern: 1-3 digits, dot, 1-3 digits, dot, 1-3 digits, dot, 1-3 digits
        # The regex does not validate octet range (0-255) — that level of
        # validation is handled by valid_ip() in ip-block.sh; here a format
        # check is sufficient since firewall-cmd will reject out-of-range values.
        if [[ "$var" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "$var"   # return the validated IP to the caller via stdout
            return
        fi
        echo "  Invalid IP, try again." >&2
    done
}

echo "=== shell-firewall.sh — enter environment IPs ==="

# Detect the primary network interface automatically from the default route.
# 'ip route' lists routing table entries; the default route line looks like:
#   default via 192.168.1.1 dev eth0 proto dhcp ...
# awk prints field 5 (the interface name) from the first line matching /default/.
# If detection fails (no default route yet), prompt the operator to enter it manually.
INTERFACE="$(ip route | awk '/default/{print $5; exit}')"
[[ -z "$INTERFACE" ]] && read -r -p "Network interface name: " INTERFACE
echo "Interface: $INTERFACE"

# Collect all five environment-specific IPs before making any firewall changes.
# This way, if the operator makes a typo and exits partway through, no partial
# rules have been applied.
SCORING_IP=$(ask_ip    "Scoring engine IP     ")  # IP of the NCAE scoring bot
EXTERNAL_KALI=$(ask_ip "Team Kali IP          ")  # our Kali workstation's IP
DHCP_SERVER=$(ask_ip   "DHCP server IP        ")  # DHCP server for the competition subnet
DNS_SERVER=$(ask_ip    "DNS server IP         ")  # our dns VM's IP (outbound DNS allowed here only)
REPO_MIRROR=$(ask_ip   "Repo mirror IP        ")  # package mirror (outbound HTTP/HTTPS allowed here only)
echo ""

# =============================================================================
# SCORING ZONE
# =============================================================================
# The scoring engine connects inbound to check that SSH and SMB services are
# running and responding correctly. We create a dedicated zone for it so that
# its source IP is the only one that can reach those services.
#
# This is safer than opening SSH/SMB in the 'public' zone, which would expose
# them to the entire network.

# Create the zone (will error if it already exists — that is fine)
firewall-cmd --permanent --new-zone=scoring

# Restrict this zone to traffic sourced from the scoring engine's IP only.
# Any packet arriving at our interface that does NOT come from SCORING_IP
# cannot enter this zone and falls through to the 'drop' zone instead.
firewall-cmd --permanent --zone=scoring --add-source=${SCORING_IP}

# Allow Samba (TCP 445, UDP 137-138, TCP 139) — scored service on the shell VM
firewall-cmd --permanent --zone=scoring --add-service=samba

# Allow SSH (TCP 22) — scored service; scoring engine verifies SSH login works
firewall-cmd --permanent --zone=scoring --add-service=ssh

# Allow ICMP — some scoring checks send ping; the shell VM must respond
firewall-cmd --permanent --zone=scoring --add-protocol=icmp

# Rate-limit SSH connections from the scoring engine to 5 per minute.
# The scoring engine checks SSH at predictable intervals; this limit is generous
# enough to pass all scoring checks while preventing brute-force if the scoring
# engine IP is spoofed.
firewall-cmd --permanent --zone=scoring --add-rich-rule='rule service name="ssh" limit value="5/m" accept'

# Set zone target to ACCEPT: packets from SCORING_IP that match an allowed
# service are accepted. Packets that don't match any service are still dropped
# (zone rules apply before the target).
firewall-cmd --permanent --zone=scoring --set-target=ACCEPT

# =============================================================================
# MANAGEMENT ZONE (our team Kali workstation)
# =============================================================================
# We need SSH access from our Kali workstation throughout the competition to
# apply hardening, run scripts, and investigate alerts. This zone allows SSH
# from our Kali IP only — no other machine can SSH in through this zone.

firewall-cmd --permanent --new-zone=mgmt-kali

# Restrict to our Kali workstation's IP
firewall-cmd --permanent --zone=mgmt-kali --add-source=${EXTERNAL_KALI}

# Allow SSH from our management machine
firewall-cmd --permanent --zone=mgmt-kali --add-service=ssh

# Allow ICMP so we can ping the VM from Kali to verify connectivity
firewall-cmd --permanent --zone=mgmt-kali --add-protocol=icmp

# Accept all traffic from our Kali machine (we trust our own workstation)
firewall-cmd --permanent --zone=mgmt-kali --set-target=ACCEPT

# =============================================================================
# DHCP TRUST ZONE
# =============================================================================
# The VM needs to communicate with the DHCP server to acquire and renew its
# IP lease. We allow DHCP traffic (UDP 67/68) only from the known DHCP server.

firewall-cmd --permanent --new-zone=dhcp-trust
firewall-cmd --permanent --zone=dhcp-trust --add-source=${DHCP_SERVER}
firewall-cmd --permanent --zone=dhcp-trust --add-service=dhcp    # UDP 67 (server) and 68 (client)
firewall-cmd --permanent --zone=dhcp-trust --set-target=ACCEPT

# =============================================================================
# DROP ZONE — assign the interface (default-deny inbound)
# =============================================================================
# Assign the physical interface to the built-in 'drop' zone.
# The drop zone target is DROP: any packet that arrives on this interface and
# is NOT matched by a source-IP rule in scoring, mgmt-kali, or dhcp-trust is
# silently discarded. This is the equivalent of a default-deny INPUT policy.

# Assign our interface to the drop zone
firewall-cmd --permanent --zone=drop --add-interface=${INTERFACE}

# Temporarily allow DHCP in the drop zone as well — the DHCP client sends
# its initial discovery broadcast before it has an assigned IP, so the
# source-based dhcp-trust zone cannot match it yet. Comment this line out
# once the VM has a stable IP assignment.
firewall-cmd --permanent --zone=drop --add-service=dhcp
# NOTE: Remove the line above once IP is confirmed stable:
#   firewall-cmd --permanent --zone=drop --remove-service=dhcp && firewall-cmd --reload

# =============================================================================
# OUTBOUND RULES (direct iptables — OUTPUT chain)
# =============================================================================
# firewalld zones only control inbound traffic. To restrict what this VM can
# send outbound (preventing reverse shells from phoning home), we inject rules
# directly into the kernel's OUTPUT chain using firewall-cmd --direct.
#
# Priority numbers control evaluation order: lower number = evaluated first.
# Rules are evaluated in ascending priority order until one matches.

# Priority 0: DROP packets in INVALID connection state.
# INVALID packets are not part of any known connection — they are often used
# in port scanning and connection hijacking attacks. Drop them before anything else.
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 \
    -m state --state INVALID -j DROP

# Priority 1: ACCEPT packets that are part of an already-established connection
# or are related to one (e.g., ICMP error responses).
# This allows responses to outbound connections we initiated (DNS lookups,
# package downloads) to flow back in without needing per-service return rules.
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 1 \
    -m state --state ESTABLISHED,RELATED -j ACCEPT

# Priority 2a: Allow outbound DNS queries to our dns VM only, UDP, max 512 bytes.
# The 512-byte length limit matches standard DNS query size. Large UDP packets
# to port 53 may indicate DNS tunneling — a covert channel attackers use to
# exfiltrate data or receive commands through a firewall that allows DNS.
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 \
    -p udp -d ${DNS_SERVER} --dport 53 -m length --length 0:512 -j ACCEPT

# Priority 2b: Allow outbound DNS over TCP to our dns VM.
# TCP is used for DNS zone transfers and responses larger than 512 bytes.
# We restrict this to our dns VM only.
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 \
    -p tcp -d ${DNS_SERVER} --dport 53 -j ACCEPT

# Priority 2c: Allow outbound HTTP/HTTPS to the repo mirror only.
# This permits package installations (dnf install) if needed during competition.
# --dports uses the multiport extension to match both 80 and 443 in one rule.
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 \
    -p tcp -d ${REPO_MIRROR} -m multiport --dports 80,443 -j ACCEPT

# Priority 2d: Allow outbound DHCP (UDP ports 67 and 68).
# The DHCP client sends from port 68 to port 67. We allow this range so that
# lease renewal traffic can still reach the DHCP server.
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 \
    -p udp --dport 67:68 -j ACCEPT

# Priority 254: LOG any outbound packet that did not match any allow rule.
# The log prefix "REVERSE_SHELL_ATTEMPT:" makes these entries easy to grep for
# in journalctl. This is the key visibility rule: if a reverse shell is active,
# its outbound packets will appear in the system journal before being dropped.
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 254 \
    -j LOG --log-prefix "REVERSE_SHELL_ATTEMPT: "

# Priority 255: DROP all remaining outbound traffic.
# This is the final default-deny egress rule. Any packet that fell through all
# the allow rules above is silently discarded.
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 255 \
    -j DROP

# =============================================================================
# Apply all permanent rules to the live running configuration
# =============================================================================
# All changes above were marked --permanent (written to config files on disk).
# --reload activates them in the running kernel without requiring a reboot.
# Run this once at the end rather than after each command to minimize the
# window where rules are partially applied.
firewall-cmd --reload
