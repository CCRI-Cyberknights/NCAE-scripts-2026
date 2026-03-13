#!/bin/bash
# =============================================================================
# killpid.sh
# CCRI Cyberknights — NCAE CyberGames 2026
# =============================================================================
#
# PURPOSE:
#   Kill any process that has an active network connection but was not present
#   when piddetect.sh recorded the baseline at competition start. This targets
#   reverse shells, C2 callbacks, and backdoor processes that connect outbound
#   to attacker-controlled infrastructure.
#
# DESIGN:
#   This script is the enforcement half of the piddetect.sh / killpid.sh pair.
#   It runs continuously via pid.service (RestartSec=1m means systemd re-runs
#   it every minute after it exits). Each run:
#
#     1. Reads the PID baseline written by piddetect.sh
#     2. Queries the current set of network connection PIDs via ss
#     3. For each new PID (not in baseline), checks whether that process
#        owns a LISTENING socket
#     4. If it owns a listening socket, it is a server process serving
#        legitimate inbound connections — SKIP it (do not kill)
#     5. If it does NOT own a listening socket, it is an unexpected client-side
#        connection — KILL it with SIGKILL and log the event
#
# THE LISTENING SOCKET SAFETY CHECK:
#   This check is the critical safety feature that prevents killpid.sh from
#   terminating the scoring engine's connections and costing us points.
#
#   When the scoring engine connects to our SSH or SMB service, the connection
#   appears as a new PID not in the baseline (the scoring engine's connections
#   arrive after baseline was taken). Without protection, killpid.sh would kill
#   sshd's child process handling that connection.
#
#   However: sshd, apache2, postgres, smbd, and named all have listening sockets
#   (they accept inbound connections). ss -tlnp shows all processes with at
#   least one listening TCP socket. By collecting those PIDs first and excluding
#   them from the kill list, we protect all server processes regardless of what
#   connections they are currently handling.
#
#   A reverse shell process (e.g., bash -i, nc, python -c) spawned by the red
#   team does NOT have a listening socket — it only has an outbound connection.
#   Therefore it is NOT in server_pids and will be killed.
#
# WHAT GETS KILLED:
#   - Reverse shells (bash -i, sh, nc connecting outbound)
#   - Saprus C2 client if it restarts after being manually killed
#   - Any other unexpected outbound connection that is not a server process
#
# WHAT IS PROTECTED:
#   - sshd (listening on :22)
#   - apache2 / nginx (listening on :80, :443)
#   - postgres (listening on :5432)
#   - smbd (listening on :445)
#   - named (listening on :53)
#   - Any other process that owns a listening socket
#
# USAGE:
#   Run piddetect.sh first to create the baseline, then:
#     systemctl enable --now pid.service   (runs killpid.sh continuously)
#   Or manually for one pass:
#     sudo bash monitoring/killpid.sh
#
# LOGGING:
#   /var/log/killpid.log — timestamped record of every PID killed.
#   'wall' broadcasts kills to all logged-in terminals in real time.
#
# DEPENDENCIES:
#   ss, grep, kill — all ship on Rocky Linux 9 and Ubuntu 24.04 without extra packages.
# =============================================================================

# Path to the baseline file created by piddetect.sh.
# Must match the LOGFILE variable in piddetect.sh exactly.
BASELINE="/var/log/connections.log"

# Path to our kill action log. Separate from BASELINE so kills never
# accidentally modify the baseline we are comparing against.
KILLLOG="/var/log/killpid.log"

# Enforce root: killing processes owned by other users and reading all socket
# process info via ss -p both require elevated privileges.
[[ "$EUID" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

# Verify the baseline exists before doing anything.
# If piddetect.sh was never run, we have no reference point and cannot
# distinguish legitimate PIDs from malicious ones. Abort with an error rather
# than defaulting to killing everything.
if [[ ! -f "$BASELINE" ]]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: no baseline at $BASELINE — run piddetect.sh first" \
        | tee -a "$KILLLOG" >&2
    exit 1
fi

# =============================================================================
# Build the server_pids list — processes that own at least one LISTENING socket
# =============================================================================
# ss -tlnp: TCP (-t), listening only (-l), numeric (-n), with process info (-p)
# grep -Eo 'pid=[0-9]+': extract all "pid=XXXX" tokens from the output
# grep -Eo '[0-9]+': strip the "pid=" prefix, leaving just the numeric PID
# sort -u: deduplicate (a process listening on multiple ports appears once)
#
# We build this list once at the start of each run, not inside the loop.
# Building it inside the loop would be slower and could give inconsistent
# results if a service starts or stops mid-run.
server_pids=$(ss -tlnp | grep -Eo 'pid=[0-9]+' | grep -Eo '[0-9]+' | sort -u)

# =============================================================================
# Compare current connections against baseline and kill unexpected ones
# =============================================================================
# ss -tunap: TCP+UDP, all states, numeric, with process info (same flags as piddetect.sh)
# grep -Eo 'pid=[0-9]+': extract PID tokens
# sort -u: deduplicate
# | while read -r conn: process one "pid=XXXX" token per iteration
ss -tunap | grep -Eo 'pid=[0-9]+' | sort -u | while read -r conn; do

    # Check if this PID was recorded in the baseline.
    # grep -qF: silent (-q), fixed-string (-F) match.
    # If the PID is in the baseline, it was present at competition start —
    # it is an expected process. Skip it.
    grep -qF "$conn" "$BASELINE" && continue

    # Strip "pid=" prefix to get the numeric PID for kill and server_pids check.
    # ${conn#pid=} is a bash parameter expansion: remove the "pid=" prefix.
    pid="${conn#pid=}"

    # Check whether this PID is in the server_pids list.
    # grep -qw: silent, whole-word match. -w prevents "123" matching "1234".
    # If this process has a listening socket, it is a server (sshd, httpd, etc.)
    # handling inbound connections from the scoring engine or team members.
    # Do NOT kill it — that would drop the scoring engine's session and cost points.
    if echo "$server_pids" | grep -qw "$pid"; then
        continue
    fi

    # This PID is:
    #   - Not in the baseline (new since competition started)
    #   - Not a listening server process
    # Therefore it is an unexpected client-side connection. Kill it.

    msg="New unexpected connection from pid=$pid — killing"

    # tee -a: write to both stdout (visible in terminal/journal) and KILLLOG
    echo "$(date '+%Y-%m-%d %H:%M:%S') $msg" | tee -a "$KILLLOG"

    # Broadcast to all logged-in terminals so the whole team is notified
    # immediately, not just whoever is watching this script's output.
    # 2>/dev/null suppresses "wall: cannot open /dev/ttyX" errors on headless VMs.
    # || true prevents the script from aborting if wall fails entirely.
    echo "$msg" | wall 2>/dev/null || true

    # Send SIGKILL (-9) to force-terminate the process immediately.
    # SIGKILL cannot be caught or ignored by the process — unlike SIGTERM,
    # which a malicious process could intercept and ignore.
    # 2>/dev/null suppresses "No such process" if the PID exited between
    # the ss query and this kill call. || true prevents abort on that error.
    kill -9 "$pid" 2>/dev/null || true

done
