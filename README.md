# NCAE-scripts-2026 — CCRI Cyberknights
### NCAE CyberGames 2026 Regionals

Competition scripts for NCAE CyberGames 2026. Written and tested by CCRI Cyberknights for
Rocky Linux 9 and Ubuntu 24.04. All scripts require root.

---

## Repository Layout

```
firewall/
    clear-firewall.sh     Reset all firewalld zones to DROP (Rocky Linux)
    shell-firewall.sh     Configure firewalld zones with scoring + mgmt access (Rocky Linux)
    ip-block.sh           Emergency IP block/unblock — works on any VM, any firewall

monitoring/
    service-watch.sh      Detect new or modified systemd .service files in real time
    user_detection.sh     Alert on login sessions not present at competition start
    piddetect.sh          Snapshot network connection PIDs as known-good baseline
    killpid.sh            Kill processes with new connections not in the baseline
    detection.service     Systemd unit — runs user_detection.sh on a 1-minute loop
    pid.service           Systemd unit — runs killpid.sh on a 1-minute loop

tools/
    user_setup.sh         Write the known-good user baseline for user_detection.sh
    Files/busybox         Static busybox binary — trusted replacement for system tools
    Files/busybox_hash.txt  SHA256 hash to verify the busybox binary before use
```

---

## firewall/

### `clear-firewall.sh`

**Purpose:** Resets all standard firewalld zones (`public`, `external`, `home`, `internal`,
`work`, `trusted`) to a locked-down state before applying a custom configuration.

For each zone it:
- Sets the default target to `DROP` (packets not matched by a rule are silently discarded)
- Removes the default SSH service allowance
- Removes the DHCPv6 client service allowance
- Removes the `eth0` interface assignment

Use this immediately before `shell-firewall.sh` to guarantee a clean starting state.
Can also be used as an emergency full lockdown if a VM is actively compromised.

**Applies to:** Rocky Linux VMs only (`shell`, `dns`). Do not run on Ubuntu — Ubuntu uses UFW.

```bash
sudo bash firewall/clear-firewall.sh
```

---

### `shell-firewall.sh`

**Purpose:** Configures firewalld with a whitelist-only policy for the shell (Rocky Linux) VM.

Creates two custom zones:
- `scoring` — allows the NCAE scoring engine to reach SSH and SMB services. Source restricted
  to the scoring engine's IP so only that host can access those services.
- `mgmt-kali` — allows the team's Kali workstation to SSH in for management. Source restricted
  to our Kali IP.

The physical interface is assigned to the built-in `drop` zone, which silently discards
all traffic not matched by the two custom zones above (default-deny inbound).

Outbound rules (via firewalld direct/iptables OUTPUT chain):
- Drop `INVALID` state packets
- Allow `ESTABLISHED`/`RELATED` traffic (return traffic for our own connections)
- Allow DNS queries to our dns VM only, UDP max 512 bytes (prevents DNS tunneling)
- Allow HTTP/HTTPS to the repo mirror only
- **LOG any other outbound packet** with the prefix `REVERSE_SHELL_ATTEMPT:` — visible in journalctl
- Drop all remaining outbound traffic (default-deny egress)

The LOG-then-DROP rule is the key anti-reverse-shell measure: if the red team establishes
a callback, the outbound packet is both recorded and blocked.

All five environment-specific IPs (scoring engine, team Kali, DNS server, repo mirror) are
**prompted at runtime** — no hardcoded values.

**Applies to:** Rocky Linux VMs only. Run `clear-firewall.sh` first.

```bash
sudo bash firewall/shell-firewall.sh
```

---

### `ip-block.sh`

**Purpose:** Emergency tool to block a single IPv4 address on both inbound and outbound
traffic during an active attack. Automatically detects whichever firewall is running
on the current machine (firewalld, ufw, or iptables) and uses it — no OS check needed.

All block and unblock actions are logged to `/var/log/ip-block.log` with a timestamp
and the name of the operator who ran the command.

**Before blocking any IP:** confirm it is not the scoring engine. Blocking the scoring
engine will cost you points.

**Applies to:** Any VM, any firewall stack.

```bash
sudo bash firewall/ip-block.sh <IP>             # block
sudo bash firewall/ip-block.sh --unblock <IP>   # remove block
sudo bash firewall/ip-block.sh --list           # show all currently blocked IPs
```

---

## monitoring/

### `service-watch.sh`

**Purpose:** Watches systemd unit directories for new or modified `.service` files.
Installing a malicious systemd service is a common red-team persistence technique —
it lets their payload survive a process kill by having systemd restart it automatically.
This script catches that the moment the file appears on disk.

Watches four directories: `/etc/systemd/system`, `/run/systemd/system`,
`/lib/systemd/system`, `/usr/lib/systemd/system` (skips any that don't exist).

Two detection modes, selected automatically:
- **inotify mode** (if `inotify-tools` is installed): kernel-level real-time detection,
  zero polling delay.
- **Polling mode** (fallback, no packages needed): checks with `find -newer` every 5 seconds.

When a change is detected, it prints the file path and `ExecStart` line so the operator
can assess the service immediately, then prompts to mask the unit with a 30-second
auto-skip. Masking stops the service, disables it, and creates a `/dev/null` symlink
that prevents it from starting even if the file is recreated.

All events logged to `/var/log/service-watch.log`.

Run in a persistent tmux pane for the entire competition:

```bash
tmux new-session -d -s watch 'sudo bash monitoring/service-watch.sh'
```

**Applies to:** All VMs. No packages required.

---

### `user_detection.sh`

**Purpose:** Detects and alerts on any active login session that was not present when
`tools/user_setup.sh` was run at competition start.

On each run it queries the system's login accounting database (`who`), deduplicates
usernames, and checks each one against `/var/log/knownusers.log`. Any username not in
the baseline triggers a `wall` broadcast to all logged-in terminals and an entry in
`/var/log/detectlog.log`.

The script runs once and exits. `detection.service` re-runs it every minute.

**Must run `tools/user_setup.sh` first** — if the baseline file does not exist, every
active user will appear as unauthorized.

**Applies to:** All VMs.

---

### `detection.service`

Systemd unit file that runs `user_detection.sh` on a continuous 1-minute loop.
The script exits after one pass; systemd restarts it after 1 minute (`RestartSec=1m`).

**Install:**
```bash
cp monitoring/detection.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now detection.service
systemctl status detection.service
```

---

### `piddetect.sh`

**Purpose:** One-time baseline snapshot. Records the PIDs of all processes that currently
have active network connections to `/var/log/connections.log`. This baseline is the
reference that `killpid.sh` uses to identify new, unexpected connections.

**Timing is critical.** Run this:
- AFTER all expected services are running (sshd, apache2, postgres, smbd, named)
- AFTER Saprus C2 and backdoor processes have been killed
- BEFORE starting `pid.service`

If run too early (before services start), legitimate service connections will be flagged.
If run too late (after the red team is already in), their PIDs will be whitelisted.

**Applies to:** All VMs.

```bash
sudo bash monitoring/piddetect.sh
```

---

### `killpid.sh`

**Purpose:** On each run, compares current network connection PIDs against the baseline
written by `piddetect.sh`. Any PID that is new AND does not own a listening socket is
killed with SIGKILL.

**The listening socket safety check** is the key design feature that prevents this script
from killing the scoring engine's connections. When the scoring engine connects inbound
to our SSH or SMB service, the connection is handled by a child of sshd or smbd — both
of which have listening sockets. Any process with a listening socket is a server and
is never killed. A reverse shell spawned by the red team has no listening socket and
will be killed.

All kills are logged to `/var/log/killpid.log` and broadcast via `wall`.

The script runs once and exits. `pid.service` re-runs it every minute.

**Must run `piddetect.sh` first.**

**Applies to:** All VMs.

---

### `pid.service`

Systemd unit file that runs `killpid.sh` on a continuous 1-minute loop.

**Install:**
```bash
cp monitoring/pid.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pid.service
systemctl status pid.service
```

---

## tools/

### `user_setup.sh`

**Purpose:** Writes the known-good user baseline for `user_detection.sh`. Queries all
currently active login sessions and appends deduplicated usernames to
`/var/log/knownusers.log`.

**Run this AFTER:**
- The `blueteam` user has been created and logged in
- Backdoor accounts (`ansible`, `redteam`, `nobody`, `www-data`) have been locked
- Team members are settled in on their machines

Running it too early (before `blueteam` is created) means `blueteam` will trigger false
alarms from `user_detection.sh` every minute for the rest of the competition.

```bash
sudo bash tools/user_setup.sh
```

---

### `tools/Files/busybox`

Static busybox binary compiled without shared library dependencies. If you suspect the
host's system binaries (`ls`, `ps`, `netstat`, etc.) have been tampered with or replaced
by the red team, use busybox as a trusted alternative.

**Always verify the hash before use:**
```bash
sha256sum tools/Files/busybox
cat tools/Files/busybox_hash.txt
# The two hashes must match exactly
```

Example usage:
```bash
./tools/Files/busybox ls /etc
./tools/Files/busybox ps aux
./tools/Files/busybox netstat -tuln
```

---

## Correct Run Order

### Step A — On every VM (universal)

Run these in order. Do not run `user_setup.sh` until step 8.

```
1.  tools/user_setup.sh             ← NO. Do not run yet.

1.  Create blueteam user:
      adduser blueteam
      usermod -aG sudo blueteam      # Ubuntu
      usermod -aG wheel blueteam     # Rocky Linux

2.  Lock backdoor accounts:
      usermod -L ansible
      usermod -L redteam
      usermod -s /usr/sbin/nologin nobody
      usermod -s /usr/sbin/nologin www-data

3.  Wipe red team SSH keys:
      > /root/.ssh/authorized_keys

4.  Deploy team SSH key to blueteam:
      mkdir -p /home/blueteam/.ssh
      echo "<team-public-key>" >> /home/blueteam/.ssh/authorized_keys
      chown -R blueteam:blueteam /home/blueteam/.ssh
      chmod 700 /home/blueteam/.ssh && chmod 600 /home/blueteam/.ssh/authorized_keys

5.  Kill Saprus C2:
      pkill -f sentinel; pkill -f saprus; pkill -f spawner

6.  Run piddetect.sh (connection baseline — after services up, after Saprus killed):
      sudo bash monitoring/piddetect.sh

7.  Log in as blueteam. Confirm SSH key works before locking root.

8.  Run user_setup.sh (user baseline — NOW, after blueteam is in and backdoors are gone):
      sudo bash tools/user_setup.sh

9.  Start monitoring services:
      cp monitoring/detection.service monitoring/pid.service /etc/systemd/system/
      systemctl daemon-reload
      systemctl enable --now detection.service pid.service

10. Start service-watch in tmux:
      tmux new-session -d -s watch 'sudo bash monitoring/service-watch.sh'
```

### Step B — Rocky Linux VMs only (shell, dns)

```
11. sudo bash firewall/clear-firewall.sh
12. sudo bash firewall/shell-firewall.sh
```

### Step C — Any VM, any time (emergency)

```
sudo bash firewall/ip-block.sh <attacker-IP>
```

---

## OS Compatibility

| Script | Ubuntu 24.04 | Rocky Linux 9 |
|---|---|---|
| `clear-firewall.sh` | No (uses firewalld) | Yes |
| `shell-firewall.sh` | No (uses firewalld) | Yes |
| `ip-block.sh` | Yes (ufw backend) | Yes (firewalld backend) |
| `service-watch.sh` | Yes | Yes |
| `user_detection.sh` | Yes | Yes |
| `detection.service` | Yes | Yes |
| `piddetect.sh` | Yes | Yes |
| `killpid.sh` | Yes | Yes |
| `pid.service` | Yes | Yes |
| `user_setup.sh` | Yes | Yes |

---

## Dependencies

No script requires installing packages beyond what ships with Rocky Linux 9 or
Ubuntu 24.04. Installing `inotify-tools` upgrades `service-watch.sh` from 5-second
polling to real-time kernel event detection automatically.
