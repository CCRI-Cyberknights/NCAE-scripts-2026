#!/bin/bash
# =============================================================================
# user_setup.sh
# CCRI Cyberknights — NCAE CyberGames 2026
# =============================================================================
#
# PURPOSE:
#   Record which users are currently logged into this machine as the
#   "known-good" baseline for user_detection.sh. Run this script ONCE at
#   competition start, after the team has logged in and before starting
#   detection.service, to establish which sessions are legitimate.
#
# DESIGN:
#   This script is the setup half of the user monitoring pair:
#
#     user_setup.sh (this script) — run ONCE at competition start
#       Writes the usernames of all current login sessions to a baseline file.
#       These are the expected users: our team members who are logged in to
#       manage the machine during competition.
#
#     user_detection.sh (companion) — run continuously via detection.service
#       Compares active sessions against the baseline on every run.
#       Any username not in the baseline triggers an alert.
#
#   The approach is deliberately simple: the baseline is a plain text file
#   with one username per line. This makes it easy to inspect, edit, and
#   verify manually. If a legitimate user logs in after setup (e.g., a team
#   member switches machines), their username can be added to the file with:
#     echo "username" >> /var/log/knownusers.log
#
# TIMING:
#   Run this script AFTER all expected team members have logged in and BEFORE
#   starting detection.service. If detection.service is already running when
#   this script runs, the baseline will be correct for future checks but
#   currently-logged-in users may trigger a spurious alert until the next
#   detection.service cycle completes.
#
# HOW 'who' IS USED:
#   'who' reads the system's utmp database (/var/run/utmp), which is maintained
#   by the login system and PAM. Each line represents one active login session.
#   awk '{print $1}' extracts the username from the first column.
#   sort -u deduplicates: a user with multiple SSH sessions appears only once
#   in the baseline, preventing false duplicates in the comparison.
#   >> appends to the file rather than overwriting, so user_setup.sh can be
#   re-run if additional team members log in after initial setup.
#
# OUTPUT:
#   /var/log/knownusers.log — one username per line, deduplicated.
#   Contents are printed to stdout after writing for immediate verification.
#
# USAGE:
#   sudo bash tools/user_setup.sh
#   Then start the detection service:
#     systemctl enable --now detection.service
#
# DEPENDENCIES:
#   who  — reads utmp; ships with util-linux on Rocky Linux 9 and Ubuntu 24.04
#   awk  — text processing; ships on all Linux distributions
#   sort — deduplication; ships on all Linux distributions
# =============================================================================

# Enforce root: writing to /var/log requires elevated privileges on both distros.
[[ "$EUID" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

# Path to the baseline file consumed by user_detection.sh.
# Must match the BASELINE variable in user_detection.sh exactly.
LOGFILE="/var/log/knownusers.log"

# Create /var/log if it doesn't exist.
# dirname extracts /var/log from the full LOGFILE path.
# mkdir -p does nothing if the directory already exists.
mkdir -p "$(dirname "$LOGFILE")"

# Query active sessions and write them to the baseline.
#
# who: reads /var/run/utmp and prints one session per line, e.g.:
#   root     pts/0   2026-03-14 11:35 (192.168.1.10)
#   zachary  pts/1   2026-03-14 11:38 (192.168.1.20)
#
# awk '{print $1}': extract only the username (first field)
#
# sort -u: sort alphabetically and deduplicate. A user with two SSH sessions
#   appears once in the file so user_detection.sh doesn't emit duplicate alerts.
#
# >>: append to the file. This is intentional — if this script is run more
#   than once (e.g., after a new team member logs in), new names are added
#   without removing the ones already recorded. Duplicates from multiple runs
#   are not a problem because user_detection.sh uses grep -qxF for exact-line
#   matching, which succeeds on the first match.
who | awk '{print $1}' | sort -u >> "$LOGFILE"

# Print the baseline contents to stdout for immediate operator verification.
# The operator should confirm they see their own username and no unexpected users.
echo "Baseline written to $LOGFILE:"
cat "$LOGFILE"
