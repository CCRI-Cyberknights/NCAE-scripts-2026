# Notes about Rocky Firewall Daemon

# Linux firewall for SMB/SSH
| Zone Name | Source Device | Allowed Services | Notes / Purpose |
| :--- | :--- | :--- | :--- |
| **scoring** | Scoring Server | Samba, SSH, ICMP | Service checks; SSH rate-limited. |
| **mgmt-kali** | Admin/Kali Box | SSH, ICMP | Remote management access. |
| **dhcp-trust** | DHCP Server | DHCP | Trusted IP assignment. |
| **drop** | Unknown/Public | DHCP (Only) | Blocks unauthorized traffic. |

| Chain | Destination | Allowed Services | Notes / Purpose |
| :--- | :--- | :--- | :--- |
| **Direct** | Any | Established/Related | Allows replies to your requests. |
| **Direct** | DNS Server | DNS (Port 53) | Resolves hostnames to IPs. |
| **Direct** | Repo Mirror | HTTP/S (80/443) | Downloads system updates. |
| **Direct** | Any | DHCP (67/68) | Requests an IP from network. |
| **Direct** | **Any Other** | **LOG & DROP** | Blocks/Logs reverse shells. |

## **Firewall Verification & Monitoring**

### **Verification Commands**
Use these to confirm the script applied correctly and to see exactly what is active.

| Task | Command | Notes |
| :--- | :--- | :--- |
| **Check Active Zones** | `firewall-cmd --get-active-zones` | Confirms which interfaces are in which zones. |
| **View Inbound Rules** | `firewall-cmd --zone=scoring --list-all` | Shows allowed services for the Scoring zone. |
| **View Outbound Rules** | `firewall-cmd --direct --get-all-rules` | Shows the "jail" settings for outbound traffic. |
| **Test Config** | `firewall-cmd --reload` | Applies changes made to the script. |

---

### **Live Security Monitoring**

```bash
journalctl -kf | grep "REVERSE_SHELL_ATTEMPT"
```

# Linux Firewall Cheat Sheet: Status, Rules, & Paths

## Firewalld Daemon
`firewalld` is the high-level daemon that often manages `nftables` or `iptables` behind the scenes.

### Status & Management
| Action | Command |
| :--- | :--- |
| **Check Status** | `systemctl status firewalld` OR `firewall-cmd --state` |
| **List All Rules** | `firewall-cmd --list-all` |
| **List All Zones** | `firewall-cmd --get-active-zones` |
| **Check Direct Rules** | `firewall-cmd --direct --get-all-rules` |

### Configuration Files
* **System Defaults:** `/usr/lib/firewalld/`
* **User Configs (Check Here!):** `/etc/firewalld/`
* **Zone Files:** `/etc/firewalld/zones/`
* **Direct Rules:** `/etc/firewalld/direct.xml`
* **Services:** `/etc/firewalld/services/`

---

## 2. Nftables (Modern Engine)
The successor to iptables; default on RHEL 8+, Debian 10+, and newer Ubuntu.

### Status & Rules
| Action | Command |
| :--- | :--- |
| **Check Status** | `systemctl status nftables` |
| **View All Rules** | `nft list ruleset` |
| **List Tables** | `nft list tables` |
| **Check Specific Table** | `nft list table inet filter` |

### Configuration Files
* **Main Config:** `/etc/nftables.conf`
* **Include Directory:** `/etc/nftables/`

---

## 3. Iptables (Legacy Engine)
Used for `--direct` rules in Firewalld or by older persistence scripts.

### Status & Rules
| Action | Command |
| :--- | :--- |
| **Check Status** | `systemctl status iptables` |
| **List Rules (Standard)** | `iptables -L -n -v` |
| **List Rules (Nat Table)** | `iptables -t nat -L -n -v` |
| **View Raw Format** | `iptables-save` |

### Configuration Files
* **IPv4 Rules (RHEL):** `/etc/sysconfig/iptables` 
* **IPv4 Rules (Ubuntu):** `/etc/iptables/rules.v4`
* **IPv6 Rules:** `/etc/sysconfig/ip6tables` OR `/etc/iptables/rules.v6`

---

## 4. Quick "Red Team" Check Commands
Run these to see if anything is hidden outside your primary firewall manager:

```bash
# See if ANY rules exist in the kernel even if firewalld looks clean
iptables-save | grep -i "ACCEPT"
nft list ruleset | grep -i "accept"

# Check for immutable bits 
lsattr /etc/firewalld/zones/
lsattr /etc/sysconfig/iptables
lsattr /etc/nftables.conf

# Check for hidden service files
ls -la /etc/firewalld/services/