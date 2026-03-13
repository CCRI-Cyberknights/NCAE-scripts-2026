#!/bin/bash
# =============================================================================
# service-watch.sh
# CCRI Cyberknights — NCAE CyberGames 2026
# =============================================================================
#
# PURPOSE:
#   Monitor systemd unit directories in real time for new or modified .service
#   files. A common red-team persistence technique is to install a malicious
#   systemd service (via a backdoor, cron job, or web shell) so that their
#   payload survives a process kill and restarts automatically. This script
#   catches that the moment the file appears on disk.
#
# DESIGN:
#   Two detection modes are implemented, selected automatically at startup:
#
#   INOTIFY MODE (preferred):
#     Uses inotifywait from the inotify-tools package to receive kernel-level
#     filesystem events the instant a .service file is created, moved into a
#     watched directory, or modified. Zero polling delay — events are detected
#     in real time as the kernel delivers them.
#
#   POLLING MODE (fallback, no packages required):
#     If inotifywait is not installed, the script falls back to checking each
#     watched directory every POLL_INTERVAL seconds using 'find -newer'. A
#     temporary timestamp file is touched after each scan; find compares each
#     .service file's mtime against that marker. This requires only standard
#     GNU coreutils, which ship on both Rocky Linux 9 and Ubuntu 24.04.
#
#   When a change is detected in either mode, handle_event() is called. It
#   prints the file path and ExecStart line so the operator can assess the
#   service immediately, then prompts to mask the unit with a 30-second
#   auto-skip timeout. All events are logged to disk regardless of the
#   operator's response.
#
# USAGE:
#   sudo bash service-watch.sh
#   Run in a persistent tmux session so it survives SSH disconnection:
#     tmux new-session -d -s watch 'sudo bash service-watch.sh'
#
# WATCHED DIRECTORIES:
#   /etc/systemd/system       — local admin units (highest priority in systemd)
#   /run/systemd/system       — runtime-generated units (used by some malware)
#   /lib/systemd/system       — distribution-provided units
#   /usr/lib/systemd/system   — package-installed units (Rocky Linux location)
#   Only directories that exist on the current machine are watched; missing
#   directories are silently skipped so the script works on both distros.
#
# MASKING:
#   When the operator confirms masking, the script calls:
#     systemctl stop    — stop the running unit immediately
#     systemctl disable — remove the unit from the boot sequence
#     systemctl mask    — create a symlink to /dev/null, making the unit
#                         impossible to start until explicitly unmasked
#   This is more complete than simply deleting the file, because systemctl mask
#   survives even if the attacker recreates the file.
#
# OUTPUT / LOGGING:
#   All events logged to /var/log/service-watch.log in the format:
#     YYYY-MM-DD HH:MM:SS EVENT <path>
#     YYYY-MM-DD HH:MM:SS MASKED <unit>
#     YYYY-MM-DD HH:MM:SS SKIPPED <unit>
#
# DEPENDENCIES:
#   Required:  bash, find, stat, grep, systemctl (all ship with both distros)
#   Optional:  inotify-tools (dnf install inotify-tools / apt install inotify-tools)
#              Install it for real-time detection; polling is the no-install fallback.
# =============================================================================

# Directories where systemd looks for unit files.
# We check all four locations because Rocky and Ubuntu place files differently:
#   Rocky Linux 9:  /usr/lib/systemd/system (packages), /etc/systemd/system (admin)
#   Ubuntu 24.04:   /lib/systemd/system (packages),     /etc/systemd/system (admin)
# /run/systemd/system holds transient units generated at runtime — some
# red-team implants use this location precisely because it is less commonly watched.
WATCH_DIRS=(
    /etc/systemd/system
    /run/systemd/system
    /lib/systemd/system
    /usr/lib/systemd/system
)

# How often (in seconds) polling mode checks for new or modified .service files.
# 5 seconds is a reasonable balance between responsiveness and CPU overhead.
POLL_INTERVAL=5

# Path to the persistent event log written throughout the competition
LOGFILE="/var/log/service-watch.log"

# ANSI terminal color codes for readability under stress
RED="\033[31m"   # alerts and masked-unit messages
BOLD="\033[1m"   # headers and highlighted output
DIM="\033[2m"    # secondary/informational text
RESET="\033[0m"  # resets all formatting

# die: fatal error — print to stderr and exit.
# Used when the environment is unsuitable to continue (no systemd dirs found).
die()    { echo "$*" >&2; exit 1; }

# stamp: returns the current timestamp in a fixed sortable format.
# Used for both terminal output and log file entries so timestamps are consistent.
stamp()  { date '+%Y-%m-%d %H:%M:%S'; }

# record: write a timestamped line to the persistent log file.
# Called on every event detection and every operator response.
record() { echo "$(stamp) $*" >> "$LOGFILE"; }

# Enforce root: systemctl mask/stop/disable require elevated privileges.
[[ "$EUID" -eq 0 ]] || die "Run as root."

# Create the log directory if it does not already exist.
# dirname extracts /var/log from the full LOGFILE path.
mkdir -p "$(dirname "$LOGFILE")"

# =============================================================================
# summarize_unit — print a human-readable summary of a .service file
# =============================================================================
# Called whenever a new or changed unit is detected. Shows three key fields:
#   File path    — so the operator knows exactly where it is on disk
#   ExecStart    — the command the service would run; malicious services almost
#                  always have a suspicious path here (e.g., /tmp/backdoor)
#   Modified     — the exact timestamp of the last modification
#
# Showing ExecStart immediately lets the operator make a masking decision in
# under 30 seconds without having to separately open and read the file.
summarize_unit() {
    local path="$1"
    local exec_line

    # grep -m1: stop after the first match. ExecStart= may appear multiple
    # times in a unit (ExecStartPre, etc.) but we only need the main command.
    # 2>/dev/null suppresses errors if the file was deleted between detection
    # and this read. || true prevents a non-zero grep exit from aborting the script.
    exec_line=$(grep -m1 '^ExecStart=' "$path" 2>/dev/null || true)

    echo -e "  ${BOLD}File:${RESET}      $path"
    # If ExecStart was not found (e.g., a .service with only [Install] stanzas),
    # show a placeholder so the operator knows the grep ran but found nothing.
    echo -e "  ${BOLD}ExecStart:${RESET} ${exec_line:-"(no ExecStart found)"}"
    # stat -c '%y': print the human-readable modification time of the file.
    # This confirms whether the file is genuinely new or an old file that was
    # just moved into the watched directory.
    echo -e "  ${BOLD}Modified:${RESET}  $(stat -c '%y' "$path" 2>/dev/null || true)"
}

# =============================================================================
# handle_event — respond to a detected .service file change
# =============================================================================
# This function is the core of the operator interaction loop. It:
#   1. Prints a high-visibility alert with the event type and file path
#   2. Calls summarize_unit to show the ExecStart line
#   3. Logs the raw event to disk
#   4. Prompts the operator to mask the unit, with a 30-second auto-skip
#      so the script does not block indefinitely if nobody is watching
#
# Arguments:
#   $1 — full path to the changed .service file
#   $2 — event type string (from inotifywait or "MODIFIED/CREATED" in poll mode)
handle_event() {
    local path="$1"
    local event="$2"
    local unit

    # basename extracts just the filename (e.g., "evil.service") from the path.
    # This is the name passed to systemctl commands, which take unit names not paths.
    unit=$(basename "$path")

    echo ""
    # Print a bold red header line with the timestamp, event type, and full path.
    # This is intentionally loud so it catches the operator's eye in a busy tmux pane.
    echo -e "${RED}${BOLD}[$(stamp)] $event — $path${RESET}"
    summarize_unit "$path"

    # Write the raw event to the log before asking the operator anything.
    # This ensures we have a record even if the operator's terminal crashes.
    record "EVENT $event $path"
    echo ""

    # Prompt with a 30-second timeout (-t 30).
    # 'read -r' prevents backslash interpretation.
    # '|| answer=""' handles the timeout case: if read exits non-zero (timeout
    # or EOF), answer is set to empty string, which the if-statement treats as "no".
    read -r -t 30 -p "  Mask $unit now? [y/N] (auto-skip in 30s): " answer || answer=""
    echo ""

    # ${answer,,} lowercases the answer so "Y", "y", and "YES" all match.
    if [[ "${answer,,}" == "y" ]]; then
        # Stop the running instance of the service immediately
        systemctl stop    "$unit" 2>/dev/null || true
        # Remove it from the boot sequence (undo any 'enable' the attacker ran)
        systemctl disable "$unit" 2>/dev/null || true
        # Mask: create a /dev/null symlink that prevents the unit from ever
        # starting again, even if the attacker rewrites the file
        systemctl mask    "$unit" 2>/dev/null || true
        # Tell systemd to re-read all unit files after the mask
        systemctl daemon-reload
        echo -e "  ${RED}Masked $unit.${RESET}"
        record "MASKED $unit"
    else
        # Operator chose to skip or the prompt timed out.
        # Provide a ready-made command so they can investigate manually.
        echo -e "  ${DIM}Skipped — review with: systemctl status $unit${RESET}"
        record "SKIPPED $unit"
    fi
}

# =============================================================================
# Build the active_dirs list — only include directories that exist on this host
# =============================================================================
# Not all four WATCH_DIRS locations exist on every distro. Passing a
# non-existent path to inotifywait causes an error; to 'find' it is silently
# ignored but clutters output. We pre-filter to only existing directories.
active_dirs=()
for d in "${WATCH_DIRS[@]}"; do
    # -d tests that the path exists and is a directory (not a file or symlink)
    [[ -d "$d" ]] && active_dirs+=("$d")
done

# If no systemd directories exist at all, this is not a systemd-based system
# and the script cannot function. Exit cleanly with an error message.
[[ ${#active_dirs[@]} -gt 0 ]] || die "No systemd unit directories found."

# =============================================================================
# run_inotify — real-time detection using inotifywait (inotify-tools)
# =============================================================================
# inotifywait registers interest with the Linux kernel's inotify subsystem and
# blocks until the kernel reports a filesystem event. This has near-zero CPU
# overhead — the process sleeps until the kernel wakes it.
#
# We watch for three event types:
#   create   — a new file was created in the directory
#   moved_to — a file was renamed or moved into the directory from elsewhere
#   modify   — an existing file's contents were changed
# We do NOT watch 'delete' or 'moved_from' because we only care about
# new or changed service definitions, not removals.
run_inotify() {
    echo -e "${BOLD}service-watch${RESET} (inotify mode) — log: $LOGFILE"
    echo -e "${DIM}Watching: ${active_dirs[*]}${RESET}"
    echo "Press Ctrl+C to stop."
    echo ""
    record "STARTED inotify mode (pid=$$)"

    inotifywait \
        --monitor \         # keep running after the first event (continuous watch)
        --recursive \       # also watch subdirectories within each watched dir
        --event create \    # trigger on new file creation
        --event moved_to \  # trigger when a file is moved/renamed into a watched dir
        --event modify \    # trigger when an existing file's contents change
        --format '%w%f %e' \ # output format: full path (%w%f) then event name (%e)
        "${active_dirs[@]}" 2>/dev/null \
    | while read -r changed_path event_type; do
        # Filter: only act on files ending in .service — we don't care about
        # .socket, .timer, .mount, or other unit types for this competition
        [[ "$changed_path" == *.service ]] || continue

        # Verify the file still exists before calling handle_event.
        # A moved_to event for a transient file (e.g., a temp file that was
        # renamed into place and then deleted) would produce a false positive
        # if we called summarize_unit on a path that no longer exists.
        [[ -f "$changed_path" ]]           || continue

        handle_event "$changed_path" "$event_type"
    done
}

# =============================================================================
# run_polling — periodic detection using find -newer (no extra packages needed)
# =============================================================================
# This mode avoids any dependency on inotify-tools. Instead of kernel events,
# it uses a timestamp reference file and 'find -newer' to detect changes.
#
# Mechanism:
#   1. Create a temporary file (ts_file) whose mtime is "now"
#   2. Sleep for POLL_INTERVAL seconds
#   3. Run 'find -newer ts_file' to list any .service files modified since step 1
#   4. Call handle_event for each result
#   5. touch ts_file to advance the reference timestamp to "now"
#   6. Repeat from step 2
#
# The trap on EXIT ensures the temp file is cleaned up if the script is
# interrupted with Ctrl+C or killed by another process.
run_polling() {
    echo -e "${BOLD}service-watch${RESET} (polling mode, ${POLL_INTERVAL}s) — log: $LOGFILE"
    echo -e "${DIM}inotify-tools not found; install it for real-time detection:${RESET}"
    echo -e "${DIM}  Rocky:  dnf install inotify-tools${RESET}"
    echo -e "${DIM}  Ubuntu: apt install inotify-tools${RESET}"
    echo ""
    echo -e "${DIM}Watching: ${active_dirs[*]}${RESET}"
    echo "Press Ctrl+C to stop."
    echo ""
    record "STARTED polling mode (pid=$$, interval=${POLL_INTERVAL}s)"

    # mktemp creates a uniquely named temporary file, preventing collisions if
    # multiple instances run simultaneously. The XXXXXX suffix is replaced with
    # random characters by mktemp.
    local ts_file
    ts_file=$(mktemp /tmp/svc-watch-ts.XXXXXX)

    # Remove the temp file on script exit (normal or abnormal) so we don't
    # leave stale files in /tmp. EXIT fires on Ctrl+C, kill, and normal return.
    trap 'rm -f "$ts_file"' EXIT

    while true; do
        # Wait before the next scan. This is at the top of the loop so the
        # initial scan (right after startup) does not flag pre-existing services
        # that are newer than the just-created ts_file.
        sleep "$POLL_INTERVAL"

        # find -print0 / read -d '' use null bytes as delimiters, handling
        # filenames that contain spaces or special characters safely.
        # -newer "$ts_file": only return files whose mtime is strictly newer
        # than ts_file's mtime — i.e., modified since our last scan.
        while IFS= read -r -d '' changed_path; do
            # Verify the file still exists (it could be created and deleted
            # within the same poll interval, which would be an FP)
            [[ -f "$changed_path" ]] || continue
            handle_event "$changed_path" "MODIFIED/CREATED"
        done < <(find "${active_dirs[@]}" \
                    -name "*.service" \
                    -newer "$ts_file" \
                    -print0 2>/dev/null)

        # Advance the timestamp reference to now so the next poll only reports
        # files changed since this scan completed, not since the last one.
        touch "$ts_file"
    done
}

# =============================================================================
# Entry point — pick the best available detection method
# =============================================================================
# command -v inotifywait: returns 0 (true) if inotifywait is in PATH.
# We check for the binary rather than the package because the binary name is
# consistent across distros even if the package name differs.
if command -v inotifywait &>/dev/null; then
    run_inotify
else
    run_polling
fi
