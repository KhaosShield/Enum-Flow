# HTB Enumeration Tool v1.0rc1

<div align="center">

![Version](https://img.shields.io/badge/version-1.0rc1-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen.svg)

**Comprehensive automated enumeration tool for HackTheBox labs and CTF challenges**

</div>

---

## Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is designed for authorized penetration testing, HackTheBox/CTF platforms, security research, and educational purposes. You are responsible for obtaining proper authorization and complying with all applicable laws. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

---

## Overview

A Python-based enumeration tool that automates reconnaissance for HackTheBox labs and CTF challenges. It conducts systematic enumeration across multiple attack vectors, generates detailed reports, and integrates popular security tools into a single workflow.

## Features

### Core Capabilities

- Automated port discovery and service enumeration with nmap
- Hostname detection with automatic /etc/hosts integration  
- Web directory brute-forcing with configurable recursion depth
- Virtual host and subdomain discovery
- Active Directory enumeration with NetExec integration
- Multi-service protocol enumeration (SMB, LDAP, DNS, FTP, SSH, etc.)
- SSL/TLS certificate analysis and vulnerability testing
- Comprehensive markdown report generation

### Advanced Enumeration

- Web vulnerability scanning with Nikto
- CMS detection and enumeration (WordPress, Joomla, Drupal)
- SSL/TLS security testing with TestSSL.sh
- Nuclei vulnerability scanning integration
- NFS share enumeration
- SNMP community string discovery
- NetBIOS and RPC enumeration  
- Impacket-based Kerberos attacks

See [ADVANCED_ENUMERATION.md](ADVANCED_ENUMERATION.md) for detailed information.

## Requirements

### Required Tools

- nmap - Network scanner
- gobuster - Directory/DNS brute-forcing
- netexec - Network protocol exploitation

### Optional Tools

Enhance functionality with these optional tools:

- feroxbuster, ffuf - Advanced web fuzzing
- smbclient, smbmap - SMB enumeration
- ldapsearch - LDAP queries
- dig, dnsenum - DNS enumeration
- whatweb - Technology detection
- enum4linux - Legacy SMB/LDAP enumeration
- nikto, wpscan - Web vulnerability scanning
- testssl.sh, sslscan - SSL/TLS testing
- nbtscan, onesixtyone - NetBIOS/SNMP scanning
- impacket-scripts - Python network protocols

### Python Requirements

- Python 3.8 or higher
- rich library (auto-installed if missing)

## Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/khaosshield/htb-enum.git
cd htb-enum

# Run the installer
chmod +x install.sh
sudo ./install.sh
```

### Manual Installation

**Install required tools:**
```bash
sudo apt update
sudo apt install -y nmap gobuster

# Install NetExec
sudo apt install -y pipx
pipx install git+https://github.com/Pennyw0rth/NetExec
```

**Install optional tools:**
```bash
sudo apt install -y feroxbuster ffuf smbclient smbmap ldap-utils \
    dnsutils dnsenum whatweb enum4linux-ng nikto wpscan testssl.sh \
    sslscan nbtscan onesixtyone snmp nfs-common impacket-scripts
```

**Install SecLists wordlists:**
```bash
sudo apt install -y seclists
```

**Install Python dependencies:**
```bash
pip install rich --break-system-packages
```

## Usage

### Basic Usage

```bash
# Interactive mode
./htb_enum.py

# Specify target IP
./htb_enum.py -t 10.10.11.123

# Quick scan (skips deep enumeration)
./htb_enum.py -t 10.10.11.123 --quick

# Stealth mode (slower, quieter)
./htb_enum.py -t 10.10.11.123 --stealth

# Custom thread count
./htb_enum.py -t 10.10.11.123 --threads 100
```

### Command-Line Options

```
-t, --target IP       Target IP address
-s, --stealth         Use stealth mode
--threads N           Number of threads (default: 50)
--quick               Quick scan (skip deep enumeration)
-h, --help            Show help message
```

## Enumeration Phases

The tool conducts enumeration in organized phases:

**Phase 1: Initial Port Discovery**  
Fast SYN scan across all ports to identify open services.

**Phase 2: Service & Version Detection**  
Detailed nmap scan with version detection and NSE scripts.

**Phase 3: Web Directory Enumeration**  
Recursive directory brute-forcing and common file discovery.

**Phase 4: Virtual Host Discovery**  
VHOST enumeration and subdomain discovery.

**Phase 5: DNS Enumeration**  
Zone transfer attempts and DNS record enumeration.

**Phase 6: SMB Enumeration**  
Share enumeration, null sessions, and user discovery.

**Phase 7: Active Directory Enumeration**  
NetExec scanning, AS-REP roasting, Kerberos enumeration, LDAP queries.

**Phase 8: Additional Services**  
FTP, SSH, MySQL, MSSQL, RDP, and SNMP enumeration.

**Phase 9: Web Vulnerability Assessment**  
Nikto scanning, CMS detection, SSL/TLS testing, Nuclei scanning.

**Phase 10: Protocol-Specific Deep Enumeration**  
NFS, SNMP, NetBIOS, RPC, and Impacket-based enumeration.

## Output

### Terminal Output

Color-coded terminal output with progress indicators:
- Green: Success/Found
- Yellow: Warnings/Optional  
- Cyan: Information/Progress
- Red: Errors/Failed

### Directory Structure

Results are saved in a directory named after the target IP:

```
<IP_ADDRESS>/
├── enumeration_report.md       # Comprehensive report
├── nmap_initial.txt            # Initial port scan
├── nmap_detailed.txt           # Detailed service scan
├── gobuster_port80.txt         # Web directory results
├── vhosts_ffuf.txt             # VHOST enumeration
├── netexec_*.txt               # NetExec outputs
├── dns_zone_transfer.txt       # DNS results
├── ssl_cert_*.txt              # SSL certificate info
└── [service]_port[N].txt       # Service-specific results
```

If the directory already exists, you'll be prompted to overwrite or create a timestamped directory.

### Markdown Report

A comprehensive markdown report is automatically generated with:
- Scan summary and statistics
- Discovered ports and services  
- Hostname discoveries
- Service-specific enumeration results
- Recommended next steps

## Documentation

- **README.md** - Main documentation (you are here)
- **EXAMPLES.md** - Detailed usage examples and scenarios
- **QUICKREF.md** - Quick reference card for common commands
- **ADVANCED_ENUMERATION.md** - Deep dive into enumeration capabilities
- **CONTRIBUTING.md** - Contribution guidelines
- **CHANGELOG.md** - Version history and planned features
- **SECURITY.md** - Security policy and responsible disclosure

## Performance

**Quick Scan (--quick)**  
Approximately 5-10 minutes. Covers core enumeration phases.

**Full Scan (default)**  
Approximately 30-60 minutes depending on target. Includes all phases and deep enumeration.

**Stealth Mode (--stealth)**  
Significantly slower. Reduces scan noise and avoids IDS/IPS detection.

## Configuration

Default configuration uses:
- Thread count: 50 (adjustable with --threads)
- Scan depth: 2 levels (configurable during runtime)
- Wordlists: SecLists default wordlists

## Tips

- Always start with the automated scan to establish baseline reconnaissance
- Review the complete markdown report before manual testing
- Use stealth mode when testing against IDS/IPS systems
- Reduce thread count if experiencing rate limiting
- Collected credentials should be tested across all discovered services
- Check for version-specific CVEs in discovered services

## Troubleshooting

**No ports found**  
Verify target is reachable with ping. Check firewall rules.

**Tool not found errors**  
Install missing tools from the requirements section.

**Permission denied updating /etc/hosts**  
Ensure you have sudo privileges.

**Timeout errors**  
Reduce thread count with `--threads 10`.

**NetExec not working**  
Verify installation: `netexec --version` or `nxc --version`

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas for contribution:
- Additional service enumeration modules
- Performance optimizations
- Documentation improvements
- Bug reports and fixes
- Feature requests

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Credits

This tool integrates and automates popular security tools:
- Nmap by Gordon Lyon
- Gobuster by OJ Reeves  
- NetExec by Pennyw0rth
- SecLists by Daniel Miessler
- Rich library by Will McGugan

## Support

- Issues: GitHub Issues
- Documentation: See docs directory
- Community: HackTheBox forums

---

**Version**: v1.0rc1  
**Last Updated**: January 26, 2025
