#!/bin/bash
# =============================================================================
# user_detection.sh
# CCRI Cyberknights — NCAE CyberGames 2026
# =============================================================================
#
# PURPOSE:
#   Detect and alert on any interactive login session that was not present when
#   the competition started. During competition, the red team may create backdoor
#   accounts or hijack existing ones to maintain persistent access. This script
#   runs continuously via detection.service and broadcasts a wall alert the
#   moment an unexpected user session appears.
#
# DESIGN:
#   At competition start, tools/user_setup.sh runs once and writes the usernames
#   of all currently logged-in sessions to /var/log/knownusers.log (the baseline).
#   This script is then run on a 1-minute loop by detection.service. Each run:
#     1. Queries the system's login accounting database (utmp) via 'who'
#     2. Deduplicates the list (a user may have multiple sessions)
#     3. Checks each active username against the baseline file
#     4. If a username is NOT in the baseline, it broadcasts a wall alert to
#        all logged-in terminals and appends an entry to the alert log
#
#   grep -qxF is used for baseline lookup instead of grep -q:
#     -x: match the whole line (prevents "root" from matching "groot")
#     -F: treat the pattern as a fixed string, not a regex (faster; safe for
#         usernames that might contain regex metacharacters like '+' or '.')
#
#   'wall' broadcasts the alert message to every logged-in terminal via the
#   system's write-all facility. This is appropriate in a competition context
#   where multiple team members may be logged in on the same machine and need
#   immediate notification of an intrusion.
#
# BASELINE:
#   /var/log/knownusers.log — written by tools/user_setup.sh at competition start.
#   Must exist before this script runs. If the file is missing, grep returns
#   non-zero and every active user appears as unauthorized. In that case, run
#   tools/user_setup.sh first.
#
# ALERT LOG:
#   /var/log/detectlog.log — one line per unauthorized session detected,
#   with a full timestamp so alert history is preserved across restarts.
#
# USAGE:
#   Run at competition start:      sudo bash tools/user_setup.sh
#   Then start the service:        systemctl enable --now detection.service
#   Or run manually for one pass:  sudo bash monitoring/user_detection.sh
#
# DEPENDENCIES:
#   who, awk, sort — ship with all Linux distributions
#   grep — ship with all Linux distributions
#   wall — ship with util-linux (present on both Rocky Linux 9 and Ubuntu 24.04)
# =============================================================================

# Full path to the baseline file written by user_setup.sh.
# Defining it as a variable here means it only needs to change in one place
# if the path is ever updated.
BASELINE="/var/log/knownusers.log"

# Full path to the alert log. Separate from BASELINE so the baseline is never
# accidentally modified by this script's writes.
ALERTLOG="/var/log/detectlog.log"

# Query the utmp database (login accounting) for all currently active sessions.
# 'who' reads /var/run/utmp and prints one line per session.
# awk '{print $1}' extracts only the username column (field 1).
# sort -u deduplicates: a single user with multiple SSH sessions appears once.
# We store the result in a variable rather than piping directly into the loop
# so that 'who', 'awk', and 'sort' finish before the loop starts, avoiding
# issues with the pipeline's subshell not seeing variables set inside it.
session_list=$(who | awk '{print $1}' | sort -u)

# Read each deduplicated username and check it against the baseline.
# IFS= prevents word splitting on lines with leading/trailing whitespace.
# -r prevents backslash interpretation in usernames (though unusual, possible).
while IFS= read -r session_user; do

    # grep -qxF: silent (-q), whole-line (-x), fixed-string (-F) match.
    # Returns 0 if session_user appears as a complete line in BASELINE.
    # 2>/dev/null suppresses the "No such file or directory" error if the
    # baseline hasn't been created yet.
    # && continue: if the user IS in the baseline, skip to the next iteration.
    grep -qxF "$session_user" "$BASELINE" 2>/dev/null && continue

    # This user is NOT in the baseline — compose an alert message.
    alert="UNAUTHORIZED SESSION DETECTED: ${session_user}"

    # Capture the current timestamp for the log entry.
    ts=$(date "+%Y-%m-%d %H:%M:%S")

    # Broadcast to all active terminals. 'wall' writes the message to the
    # /dev/pts/* devices of every logged-in user so all team members see it
    # simultaneously, not just whoever is watching this script's output.
    wall "$alert"

    # Append to the persistent alert log with full timestamp.
    # >> appends (does not overwrite) so the full alert history accumulates.
    echo "${ts} [SESSION ALERT] ${session_user} is not in baseline" >> "$ALERTLOG"

done <<< "$session_list"
# <<< feeds session_list as a here-string into the while loop's stdin,
# avoiding a subshell (which would prevent variable assignments inside
# the loop from being visible outside it, if we needed them).
