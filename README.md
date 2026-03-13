# NCAE-scripts-2026 — CCRI Cyberknights

Competition scripts for NCAE Cyber Games 2026. Tested on Rocky Linux 9 and Ubuntu 24.04.

---

## Layout

```
firewall/       Firewall setup and IP blocking
monitoring/     Service and process detection
tools/          User setup and trusted binaries
```

---

## firewall/

### `shell-firewall.sh`
Configures firewalld zones on the shell (Rocky Linux) VM. Creates a `scoring` zone,
a `mgmt-kali` zone for team access, a `dhcp-trust` zone, and outbound rules that log
and drop unexpected egress (reverse shell prevention). Prompts for the five
environment-specific IPs at runtime — no hardcoded values.

**Run:** `sudo bash firewall/shell-firewall.sh`
**Requires:** firewalld active

### `clear-firewall.sh`
Sets all standard firewalld zones to DROP and removes default ssh/dhcpv6 services.
Use this before `shell-firewall.sh` to start from a known-clean state, or as a fast
lockdown if the environment is actively compromised.

**Run:** `sudo bash firewall/clear-firewall.sh`
**Requires:** firewalld active

### `ip-block.sh`
Blocks or unblocks a single IP on both inbound and outbound traffic. Detects whichever
firewall is active (firewalld, ufw, or iptables) automatically. Logs all actions with
timestamp and operator name to `/var/log/ip-block.log`.

```
sudo bash firewall/ip-block.sh <IP>             # block
sudo bash firewall/ip-block.sh --unblock <IP>   # remove block
sudo bash firewall/ip-block.sh --list           # show blocked IPs
```

**Requires:** firewalld, ufw, or iptables (uses whichever is running)

---

## monitoring/

### `service-watch.sh`
Watches systemd unit directories for new or modified `.service` files. Uses
`inotifywait` for real-time detection when available; falls back to polling with
`find -newer` every 5 seconds otherwise — no package installation required.

When a change is detected, displays the file path and `ExecStart` line, then prompts
to mask the unit (with a 30-second auto-skip). All events logged to
`/var/log/service-watch.log`.

**Run:** `sudo bash monitoring/service-watch.sh`
**Requires:** nothing (inotify-tools optional for real-time mode)

### `user_detection.sh`
Monitors `/etc/passwd` and `/etc/shadow` for unauthorized changes.

**Run:** `sudo bash monitoring/user_detection.sh`

### `detection.service` / `pid.service`
Systemd unit files to run detection scripts as persistent background services.

Install: copy to `/etc/systemd/system/`, then `systemctl daemon-reload && systemctl enable --now <name>.service`

### `piddetect.sh` / `killpid.sh`
Process anomaly detection and targeted kill helpers.

---

## tools/

### `user_setup.sh`
Creates competition user accounts and sets passwords. Run once per VM during Phase 1.

**Run:** `sudo bash tools/user_setup.sh`

### `Files/busybox`
Static busybox binary. Use as a trusted replacement for system utilities if you
suspect the host binaries have been tampered with.

Verify before use:
```
sha256sum tools/Files/busybox
cat tools/Files/busybox_hash.txt
```

---

## Suggested run order

### Phase 1 — first 10 minutes on each Rocky Linux VM

1. `sudo bash tools/user_setup.sh`
2. `sudo bash firewall/clear-firewall.sh`
3. `sudo bash firewall/shell-firewall.sh`
4. `sudo bash monitoring/service-watch.sh` (keep running in a tmux pane)

### Phase 1 — on any VM (IP blocking)

```
sudo bash firewall/ip-block.sh <attacker-IP>
```

---

## Dependencies

All scripts are designed to work with tools already present on Rocky Linux 9 and
Ubuntu 24.04. No package installation is required. Installing `inotify-tools` will
upgrade `service-watch.sh` to real-time mode automatically.
