#!/bin/bash
# =============================================================================
# ip-block.sh
# CCRI Cyberknights — NCAE CyberGames 2026
# =============================================================================
#
# PURPOSE:
#   Emergency IP blocking tool for use during active red-team competition.
#   Blocks a single IPv4 address on both INBOUND and OUTBOUND traffic, so
#   that a compromised host cannot receive commands from or send data back to
#   an attacker-controlled machine.
#
# DESIGN:
#   Competition VMs run different operating systems (Ubuntu 24.04 uses UFW,
#   Rocky Linux 9 uses firewalld) and not all machines have the same firewall
#   stack installed. Rather than hardcoding an OS check, this script inspects
#   which firewall daemon is currently *active* via systemctl, then falls back
#   to raw iptables if neither managed daemon is running. This approach works
#   correctly even on a VM where the expected firewall was disabled or replaced
#   by the red team.
#
#   Each supported firewall backend has its own block/unblock/list function
#   family (fw_*, ufw_*, ipt_*). A single dispatch layer (do_block, do_unblock,
#   do_list) routes the requested operation to the correct backend. This keeps
#   each backend's logic self-contained and easy to audit.
#
# USAGE:
#   sudo bash ip-block.sh <IP>             # block an IP
#   sudo bash ip-block.sh --unblock <IP>   # remove a block
#   sudo bash ip-block.sh --list           # show currently blocked IPs
#
# SUPPORTED FIREWALLS (detected automatically):
#   firewalld  — Rocky Linux 9 default
#   ufw        — Ubuntu 24.04 default
#   iptables   — fallback; present on both distros
#
# OUTPUT:
#   All block and unblock actions are appended to /var/log/ip-block.log with a
#   timestamp and the name of the operator who invoked sudo, so there is an
#   audit trail of every IP that was blocked during the competition.
#
# DEPENDENCIES:
#   No packages beyond what ships with Rocky Linux 9 or Ubuntu 24.04.
#   Requires root (firewall changes require elevated privileges).
# =============================================================================

# Path to the persistent audit log for all block/unblock actions
LOGFILE="/var/log/ip-block.log"

# ANSI terminal color codes used to make output easier to read at a glance
# during a high-pressure competition environment
BOLD="\033[1m"   # bold text — used for status headers
RED="\033[31m"   # red — used for "blocked" confirmation
GREEN="\033[32m" # green — used for "unblocked" confirmation
RESET="\033[0m"  # resets all formatting back to terminal default

# die: print an error message to stderr and immediately exit non-zero.
# Used for unrecoverable errors (bad input, no firewall found, etc.)
die()  { echo "$*" >&2; exit 1; }

# info: print a message to stdout with echo -e so ANSI codes are interpreted.
# Used for normal status output (not errors).
info() { echo -e "$*"; }

# Enforce root: firewall commands require elevated privileges on all supported
# distros. $EUID is the effective user ID; 0 means root.
[[ "$EUID" -eq 0 ]] || die "Run as root."

# stamp: returns the current date and time in a consistent, sortable format.
# Called inline when writing log entries so every line has the same timestamp
# format regardless of locale settings on the competition VM.
stamp()  { date '+%Y-%m-%d %H:%M:%S'; }

# record: append a timestamped audit entry to the log file.
# $SUDO_USER is set by sudo to the name of the invoking user; if the script
# is run directly as root (no sudo), we fall back to the literal string "root".
# This lets us distinguish between team members in the audit trail.
record() { echo "$(stamp) [${SUDO_USER:-root}] $*" >> "$LOGFILE"; }

# =============================================================================
# valid_ip — validate that a string is a syntactically correct IPv4 address
# =============================================================================
# We check two things:
#   1. The string matches the dotted-quad pattern (four groups of 1-3 digits)
#   2. Each octet is numerically <= 255 (0-9 match the regex but 999 is invalid)
# This prevents shell injection through malformed input and gives a clean error
# instead of passing garbage to firewall commands.
valid_ip() {
    local ip="$1"

    # Regex: four groups of 1-3 digits separated by literal dots.
    # The ^ and $ anchors ensure we match the whole string, not a substring.
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    # Split the address on dots into four variables and verify each is <= 255.
    # IFS='.' temporarily changes the field separator for the read command only.
    IFS='.' read -r a b c d <<< "$ip"
    [[ "$a" -le 255 && "$b" -le 255 && "$c" -le 255 && "$d" -le 255 ]]
}

# =============================================================================
# active_firewall — detect which firewall manager is currently running
# =============================================================================
# We check daemon status rather than which packages are installed, because a
# package can be installed but not running (e.g., ufw installed but disabled).
# Calling commands against a stopped daemon fails silently; we want to talk to
# whatever is actually enforcing rules right now.
#
# Priority: firewalld > ufw > iptables (raw)
#   - firewalld is preferred on Rocky Linux 9 (zone-based, persistent by default)
#   - ufw is preferred on Ubuntu 24.04 (simple rule management, persistent)
#   - iptables is the universal fallback — present on both distros even when
#     no higher-level manager is active
active_firewall() {
    # systemctl is-active returns 0 (true) if the named service is running
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        echo "firewalld"
    elif systemctl is-active --quiet ufw 2>/dev/null; then
        echo "ufw"
    # command -v checks whether iptables is in PATH without running it
    elif command -v iptables &>/dev/null; then
        echo "iptables"
    else
        die "No supported firewall found (firewalld, ufw, or iptables)."
    fi
}

# =============================================================================
# FIREWALLD BACKEND
# =============================================================================
# firewalld uses a zone-based model. Blocking an IP requires two separate rules:
#   1. An inbound rich rule: drop all packets from the source address
#   2. A direct OUTPUT rule: drop all packets destined for the address
# --permanent makes rules survive a firewall-cmd --reload or system reboot.
# firewall-cmd --reload applies pending permanent rules to the running config.

fw_block() {
    # Inbound: rich rule drops all IPv4 packets sourced from $1
    # 'drop' silently discards packets; 'reject' sends an ICMP error back.
    # We use drop to not reveal our presence to the attacker.
    firewall-cmd --permanent \
        --add-rich-rule="rule family='ipv4' source address='$1' drop" 2>/dev/null

    # Outbound: direct rule in the OUTPUT chain drops packets destined for $1.
    # Direct rules bypass the zone model and are applied as raw iptables rules.
    # Priority 0 means this rule is inserted at the top of the OUTPUT chain.
    firewall-cmd --permanent \
        --direct --add-rule ipv4 filter OUTPUT 0 -d "$1" -j DROP 2>/dev/null

    # Apply the permanent rules to the live running configuration immediately
    firewall-cmd --reload
}

fw_unblock() {
    # Mirror of fw_block: remove both the inbound rich rule and the outbound direct rule.
    # || true prevents the script from exiting if the rule doesn't exist
    # (e.g., if unblock is called for an IP that was never blocked).
    firewall-cmd --permanent \
        --remove-rich-rule="rule family='ipv4' source address='$1' drop" 2>/dev/null || true
    firewall-cmd --permanent \
        --direct --remove-rule ipv4 filter OUTPUT 0 -d "$1" -j DROP 2>/dev/null || true

    # Reload to apply the removal to the live configuration
    firewall-cmd --reload
}

fw_list() {
    # Show all active rich rules — these include our drop rules as well as any
    # other rich rules that may have been added by the team or by red-team persistence
    echo "Inbound drops:"
    firewall-cmd --list-rich-rules 2>/dev/null | grep drop || echo "  (none)"

    # Show direct rules and filter for OUTPUT chain DROP entries specifically
    echo "Outbound drops:"
    firewall-cmd --direct --get-all-rules 2>/dev/null | grep "OUTPUT.*DROP" || echo "  (none)"
}

# =============================================================================
# UFW BACKEND
# =============================================================================
# ufw (Uncomplicated Firewall) wraps iptables with a simpler rule syntax.
# 'insert 1' places our rule at position 1 (highest priority) so it is
# evaluated before any allow rules that may already exist.

ufw_block() {
    # Block all inbound traffic from the target IP to any port on this host
    ufw insert 1 deny from "$1" to any

    # Block all outbound traffic from this host to the target IP
    ufw insert 1 deny from any to "$1"

    # Reload ufw to activate the new rules in the kernel
    ufw reload
}

ufw_unblock() {
    # Remove the deny rules added by ufw_block.
    # ufw delete finds and removes the first matching rule; || true handles
    # the case where the rule was already removed or was never added.
    ufw delete deny from "$1" to any 2>/dev/null || true
    ufw delete deny from any to "$1" 2>/dev/null || true
    ufw reload
}

ufw_list() {
    # 'ufw status numbered' shows all rules with index numbers.
    # We grep for 'deny' to show only blocking rules, not allow rules.
    ufw status numbered | grep -i deny || echo "  (none)"
}

# =============================================================================
# IPTABLES BACKEND (raw, no daemon)
# =============================================================================
# iptables rules are applied directly to the kernel netfilter tables.
# Changes are in-memory only until explicitly saved; we attempt to persist them
# via iptables-save. This fallback is used when neither firewalld nor ufw is
# running — for example, on a VM where the default firewall was stopped.

ipt_block() {
    # -I INPUT 1: insert at position 1 of the INPUT chain (highest priority)
    # -s $1: match packets with this source address (inbound)
    # -j DROP: silently discard the packet
    iptables -I INPUT  1 -s "$1" -j DROP

    # -I OUTPUT 1: insert at position 1 of the OUTPUT chain
    # -d $1: match packets destined for this address (outbound)
    iptables -I OUTPUT 1 -d "$1" -j DROP

    # Persist rules to disk so they survive a reboot.
    # /etc/iptables/rules.v4 is the standard path on Debian/Ubuntu;
    # || true silences errors on systems where the directory doesn't exist.
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
}

ipt_unblock() {
    # -D: delete the first matching rule from the chain.
    # We don't use -I here because we're removing, not inserting.
    iptables -D INPUT  -s "$1" -j DROP 2>/dev/null || true
    iptables -D OUTPUT -d "$1" -j DROP 2>/dev/null || true
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
}

ipt_list() {
    # -L INPUT OUTPUT: list both chains
    # -n: numeric output (don't resolve IPs to hostnames — faster and cleaner)
    # --line-numbers: show rule index for reference
    # grep DROP: show only drop rules, not accept rules
    iptables -L INPUT OUTPUT -n --line-numbers | grep DROP || echo "  (none)"
}

# =============================================================================
# DISPATCH LAYER
# =============================================================================
# These three functions receive an IP and a tool name, then route the call to
# the correct backend. This decouples the main logic from the backend details —
# the main section only calls do_block/do_unblock/do_list and never needs to
# know which backend is active.

do_block() {
    local ip="$1" tool="$2"
    case "$tool" in
        firewalld) fw_block  "$ip" ;;
        ufw)       ufw_block "$ip" ;;
        iptables)  ipt_block "$ip" ;;
    esac
}

do_unblock() {
    local ip="$1" tool="$2"
    case "$tool" in
        firewalld) fw_unblock  "$ip" ;;
        ufw)       ufw_unblock "$ip" ;;
        iptables)  ipt_unblock "$ip" ;;
    esac
}

do_list() {
    local tool="$1"
    info "${BOLD}Firewall: $tool${RESET}"   # show which backend is active
    case "$tool" in
        firewalld) fw_list  ;;
        ufw)       ufw_list ;;
        iptables)  ipt_list ;;
    esac
}

# =============================================================================
# MAIN
# =============================================================================

# Ensure the log directory exists before attempting to write.
# dirname extracts the directory portion of LOGFILE (/var/log).
mkdir -p "$(dirname "$LOGFILE")"

# Detect the active firewall once; all operations in this run use the same backend
tool=$(active_firewall)

# Parse the first argument to determine which operation was requested.
# ${1:-} expands to an empty string if no argument was given, preventing
# an unbound variable error when running with 'set -u'.
case "${1:-}" in

    --list)
        # Show all currently blocked IPs — no IP argument needed
        do_list "$tool"
        ;;

    --unblock)
        # Expect the IP to unblock as the second argument
        ip="${2:-}"
        valid_ip "$ip" || die "Invalid IP address: $ip"
        info "${BOLD}Unblocking $ip via $tool...${RESET}"
        do_unblock "$ip" "$tool"
        record "UNBLOCKED $ip via $tool"   # audit log entry
        info "${GREEN}Unblocked $ip${RESET}"
        ;;

    "")
        # No arguments: print usage and exit with error
        die "Usage:
  sudo bash ip-block.sh <IP>
  sudo bash ip-block.sh --unblock <IP>
  sudo bash ip-block.sh --list"
        ;;

    *)
        # Default: treat the first argument as an IP to block
        ip="$1"
        valid_ip "$ip" || die "Invalid IP address: $ip"
        info "${BOLD}Blocking $ip via $tool (inbound + outbound)...${RESET}"
        do_block "$ip" "$tool"
        record "BLOCKED $ip via $tool"   # audit log entry
        info "${RED}Blocked $ip${RESET}"
        ;;
esac
