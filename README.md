# EnumFlow v1.3

<div align="center">

![Version](https://img.shields.io/badge/version-1.3-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-lightgrey.svg)
![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen.svg)

**Comprehensive automated enumeration tool for penetration testing and CTF challenges**

*Author: [@KhaosShield](https://github.com/KhaosShield)*

</div>

---

## Overview

A Python-based enumeration tool that automates reconnaissance across penetration testing engagements and CTF challenges. It conducts systematic enumeration across multiple attack vectors, streams a live browser dashboard, and generates detailed HTML and Markdown reports.

## What's New in v1.3

### Features
- **Live browser dashboard** with real-time SSE updates — phases, ports, findings, commands
- **Prompt banner** — pulsing red alert in the browser whenever terminal input is required
- **Prompts & Status tab** — logs every terminal question with waiting/answered state
- **Markdown rendering** — finding cards render bold, code, tables, and code blocks as HTML
- **Clickable port rows** — expand service/version detail on click
- **Active-command topbar** — shows the current running command description
- **Null-result cards** — phases that complete cleanly show a muted "(no findings)" card instead of being empty
- **Dashboard keep-alive** — server stays up after scan completion so the browser remains accessible; press Ctrl+C to exit
- **Refresh after completion** — reloading the dashboard correctly replays the completed state

## What's New in v1.2

### Features
- **Live browser dashboard** at `http://127.0.0.1:5000` (Flask SSE)
- **HTML report** generated alongside the Markdown report
- **`--no-browser`** flag suppresses auto-opening the browser

## What's New in v1.1

### Features
- **Credential reuse across AD phases** — credentials are asked once and shared across BloodHound, Kerberoasting, deep share enumeration, and GPP extraction
- **enum4linux live terminal output** — streams results directly to terminal in real-time with parsed summary
- **Critical finding highlights** — exploitation paths render in a bordered red panel
- **Progress spinners on all AD phases**

### Bug Fixes
- LDAP dump no longer hangs
- NetExec credential validation fixed
- Web enumeration now detects ports 8080/8443
- Gobuster VHOST results now parsed and reported
- Shell injection via credentials prevented
- enum4linux no longer prompts for password
- NetExec DB schema errors detected with fix instructions

## Features

### Core Capabilities

- **Network range scanning** with automatic host discovery
- Automated port discovery and service enumeration with nmap
- Hostname detection with automatic /etc/hosts integration
- Web directory brute-forcing with configurable recursion depth
- Virtual host and subdomain discovery
- Active Directory enumeration with NetExec and BloodHound integration
- Multi-service protocol enumeration (SMB, LDAP, DNS, FTP, SSH, etc.)
- SSL/TLS certificate analysis and vulnerability testing
- Live browser dashboard with SSE streaming
- Comprehensive HTML and Markdown report generation

### Active Directory

- **Single credential prompt** — enter once, reused across all AD sub-phases
- **NetExec** SMB/LDAP/WinRM/RDP/MSSQL credential validation
- **LDAP fallback** for service accounts that fail SMB auth
- **BloodHound** data collection with bloodhound-python
- **Kerberoasting** via NetExec and Impacket
- **AS-REP roasting** with and without credentials
- **Deep share enumeration** for sensitive files
- **GPP password extraction** from SYSVOL
- **Credential matrix** — tests creds against all discovered services
- **Exploitation panel** — highlighted psexec, evil-winrm, secretsdump commands

### SMB Enumeration

- Null session and guest access detection
- enum4linux with **live terminal streaming** and parsed results
- Share discovery and user enumeration

### Advanced Enumeration

- Web vulnerability scanning with Nikto
- CMS detection and enumeration (WordPress, Joomla, Drupal)
- SSL/TLS security testing with TestSSL.sh
- Nuclei vulnerability scanning integration
- NFS share enumeration
- SNMP community string discovery
- NetBIOS and RPC enumeration

---

## Requirements

### Required Tools

- nmap - Network scanner
- gobuster - Directory/DNS brute-forcing
- netexec - Network protocol exploitation

### Optional Tools

| Category | Tools |
|----------|-------|
| Web Fuzzing | feroxbuster, ffuf |
| SMB/AD | smbclient, smbmap, enum4linux, bloodhound-python |
| LDAP/Kerberos | ldapsearch, kerbrute, impacket-scripts |
| DNS | dig, dnsenum |
| Web Scanning | whatweb, nikto, wpscan, joomscan, sqlmap |
| SSL/TLS | testssl.sh, sslscan |
| Network | nbtscan, onesixtyone, responder, ssh-audit |

### Python Requirements

- Python 3.8 or higher
- rich library (auto-installed if missing)
- flask library (for browser dashboard)
- bloodhound library (installed via install.sh)

## Installation

### Quick Install (Kali Linux)

```bash
git clone https://github.com/KhaosShield/enumflow.git
cd enumflow
chmod +x install.sh
sudo ./install.sh
```

The installer will:
- Install all required and optional tools
- Install Python dependencies (rich, bloodhound, flask)
- Download kerbrute from GitHub
- Optionally create a global symlink (`enumflow`)

---

## Usage

### Basic Usage

```bash
# Interactive mode
./enumflow.py

# Specify target IP
./enumflow.py -t 10.10.11.123

# Network range
./enumflow.py -t 10.10.110.0/24

# IP range notation
./enumflow.py -t 10.10.110.1-254

# Quick scan (skips deep enumeration)
./enumflow.py -t 10.10.11.123 --quick

# Stealth mode (slower, quieter)
./enumflow.py -t 10.10.11.123 --stealth

# Suppress auto-opening browser
./enumflow.py -t 10.10.11.123 --no-browser
```

### Command-Line Options

```
-t, --target TARGET   Target IP, CIDR (10.10.110.0/24), or range (10.10.110.1-254)
-s, --stealth         Use stealth mode (slower, quieter scans)
--threads N           Number of threads (default: 50)
--quick               Quick scan (skip deep enumeration)
--no-browser          Disable auto-opening browser dashboard
-h, --help            Show help message
```

### Controls During Execution

| Key | Action |
|-----|--------|
| Ctrl+C | Exit script (or close dashboard after scan completes) |
| Ctrl+Z | Skip current phase (then type `fg` + Enter to continue) |

## Enumeration Phases

### Single Host Mode

**Phase 1: Initial Port Discovery**
Fast SYN scan across all ports to identify open services.

**Phase 2: Service & Version Detection**
Detailed nmap scan with version detection and NSE scripts.

**Phase 3: Hostname Integration**
Automatic /etc/hosts update with discovered hostnames.

**Phase 4: SSL Certificate Analysis**
Extract information from SSL/TLS certificates.

**Phase 5: Web Enumeration**
Directory brute-forcing, VHOST discovery, technology detection. Supports ports 80, 443, 8080, and 8443.

**Phase 6: DNS Enumeration**
Zone transfer attempts and DNS record enumeration.

**Phase 7: Active Directory Enumeration**
Single credential prompt with NetExec SMB/LDAP enumeration, BloodHound collection, Kerberoasting, AS-REP roasting, deep share search, and GPP password extraction.

**Phase 8: SMB Enumeration**
Share enumeration, null sessions, user discovery, enum4linux with live terminal output.

**Phase 9: Additional Services**
FTP, SSH, MySQL, MSSQL, RDP, SNMP enumeration.

**Phase 10: Advanced Web Assessment**
Nikto, CMS detection, SSL testing, Nuclei scanning.

### Network Range Mode

**Phase 0: Host Discovery**
Ping sweep to identify live hosts in the network range.

**Host Selection**
Interactive selection of which host(s) to enumerate.

**Per-Host Enumeration**
Full enumeration pipeline runs for each selected host.

## Output

### Directory Structure

**Single Host:**
```
<IP_ADDRESS>/
├── enumeration_report.md       # Markdown report
├── enumeration_report.html     # HTML report (browser-friendly)
├── nmap_initial.txt            # Initial port scan
├── nmap_detailed.txt           # Detailed service scan
├── enum4linux.txt              # enum4linux full output
├── gobuster_port80.txt         # Web directory results
├── netexec_*.txt               # NetExec outputs
├── credential_validation.txt   # Credential test results
├── asrep_hashes.txt            # AS-REP roastable hashes
├── kerberoast_hashes.txt       # Kerberoastable hashes
└── [service]_port[N].txt       # Service-specific results
```

**Network Range:**
```
10.10.110.0_24/
├── host_discovery.txt          # Live host scan results
├── enumeration_report.md       # Combined report
├── 10_10_110_2/               # Per-host subdirectory
│   └── ...
└── ...
```

### Terminal Output

Color-coded terminal output with progress indicators:
- **Green**: Success/Found
- **Yellow**: Warnings/Optional
- **Cyan**: Information/Progress
- **Red**: Errors/Critical findings/Exploitation paths
- **Bold Yellow**: Exploit commands (copy-paste ready)

---

## Troubleshooting

**No ports found**
Verify target is reachable with ping. Check firewall rules.

**Tool not found errors**
Run `sudo ./install.sh` to install missing tools.

**Permission denied updating /etc/hosts**
Run with sudo: `sudo ./enumflow.py`

**Timeout errors on large networks**
Use single host mode or reduce scope.

**NetExec schema mismatch error**
Remove the stale database: `rm -f ~/.nxc/workspaces/default/smb.db`

**enum4linux timeout**
The tool has a 10-minute timeout. Use Ctrl+Z to skip if needed.

**Dashboard not updating after scan finishes**
The scan keeps the dashboard server alive — press Ctrl+C in the terminal to exit.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Credits

This tool integrates and automates popular security tools:
- Nmap by Gordon Lyon
- Gobuster by OJ Reeves
- NetExec by Pennyw0rth
- BloodHound by SpecterOps
- enum4linux by Mark Lowe
- Impacket by SecureAuth
- SecLists by Daniel Miessler
- Rich library by Will McGugan

---

**Version**: v1.3
**Author**: [@KhaosShield](https://github.com/KhaosShield)
