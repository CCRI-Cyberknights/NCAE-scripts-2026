#!/bin/bash
# =============================================================================
# piddetect.sh
# CCRI Cyberknights — NCAE CyberGames 2026
# =============================================================================
#
# PURPOSE:
#   Snapshot the process IDs of all processes that currently have active network
#   connections. This snapshot becomes the "known-good baseline" that killpid.sh
#   uses to identify NEW network connections that appear after competition starts.
#
# DESIGN:
#   This script is the setup half of a two-part detection system:
#
#     piddetect.sh (this script) — run ONCE at competition start
#       Records which PIDs have network connections right now.
#       These are expected processes: sshd, apache2, postgres, named, smbd, etc.
#
#     killpid.sh (companion script) — run continuously via pid.service
#       Compares current connection PIDs against the baseline.
#       Kills any PID that is new AND does not own a listening socket.
#
#   The rationale: when the red team establishes a reverse shell or plants a
#   backdoor that connects outbound, a new process with a network connection
#   appears that was not in the baseline. killpid.sh catches this.
#
#   By recording PIDs rather than connection details (IP/port), the baseline
#   captures the identity of the process, not just what it was connected to.
#   This means even a process that rotates its destination (e.g., Saprus C2)
#   is detected the first time it establishes any connection after baseline.
#
# HOW ss IS USED:
#   ss -tunap lists all TCP (-t) and UDP (-u) sockets that are not listening
#   (-a would include listening; without -a only ESTABLISHED connections show),
#   including the process (-p) that owns each socket, in numeric format (-n).
#   The output includes a 'users:(("process",pid=XXXX,fd=X))' field for each
#   socket. grep -Eo 'pid=[0-9]+' extracts just the "pid=XXXX" tokens.
#   sort -u deduplicates (a process with multiple connections appears once).
#
# TIMING:
#   Run this script AFTER:
#     - All expected services are started (sshd, apache2, postgres, etc.)
#     - tools/user_setup.sh has been run
#     - Saprus C2 and backdoors have been killed (so they are NOT in the baseline)
#   Running it too early (before services start) would give an incomplete
#   baseline and flag legitimate service connections as suspicious.
#   Running it too late (after red team gains access) would include malicious
#   PIDs in the baseline and make killpid.sh ignore them.
#
# USAGE:
#   sudo bash monitoring/piddetect.sh
#   Run once at competition start. Output is appended (not overwritten) so it
#   can be run again if a new service starts after initial setup.
#
# OUTPUT:
#   /var/log/connections.log — one "pid=XXXX" entry per line, deduplicated.
#
# DEPENDENCIES:
#   ss     — socket statistics; ships with iproute2 on both Rocky 9 and Ubuntu 24.04
#   grep   — standard; ships on all Linux distros
#   sort   — standard; ships on all Linux distros
# =============================================================================

# Enforce root: ss -p (process names) requires elevated privileges to show
# process ownership for sockets owned by other users.
[[ "$EUID" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

# Path to the baseline file consumed by killpid.sh.
# Must match the BASELINE variable in killpid.sh exactly.
LOGFILE="/var/log/connections.log"

# Create /var/log if it doesn't exist (unusual but safe to ensure).
# dirname extracts /var/log from the full path.
mkdir -p "$(dirname "$LOGFILE")"

# Query all active (non-listening) TCP and UDP connections and extract PIDs.
#
# ss flags used:
#   -t  : TCP sockets only (not UNIX domain, not raw)
#   -u  : UDP sockets (DNS clients, DHCP, NTP often show here)
#   -n  : numeric — do not resolve IP addresses or port numbers to names
#         (faster; avoids DNS lookups that could fail during competition)
#   -a  : all sockets, including LISTEN state (we want to capture server PIDs
#         too, so killpid.sh can recognize them as safe)
#   -p  : show the process that owns each socket (requires root)
#
# grep -Eo 'pid=[0-9]+': -E enables extended regex, -o prints only the match.
#   The pattern 'pid=[0-9]+' matches the "pid=XXXX" substring in the users field.
#
# sort -u: sort numerically and remove duplicates. A process with multiple
#   sockets (e.g., sshd handling several SSH sessions) appears once.
#
# >>: append to the baseline file. Using append instead of overwrite allows
#   piddetect.sh to be re-run if additional services start after initial setup.
ss -tunap | grep -Eo "pid=[0-9]+" | sort -u >> "$LOGFILE"

# Print confirmation so the operator can verify the baseline was written.
echo "Baseline written to $LOGFILE:"
cat "$LOGFILE"
