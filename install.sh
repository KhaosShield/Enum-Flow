#!/bin/bash

set -e


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║     HTB Enumeration Tool v1.0 - Installer              ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}[!] This script requires root privileges${NC}"
    echo -e "${YELLOW}[!] Please run with sudo: sudo ./install.sh${NC}"
    exit 1
fi

echo -e "${BLUE}[*] Starting installation...${NC}\n"

# Update package list
echo -e "${BLUE}[*] Updating package list...${NC}"
apt update -qq

# Install required tools
echo -e "\n${BLUE}[*] Installing required tools...${NC}"

REQUIRED_TOOLS=(
    "nmap"
    "gobuster"
    "python3"
    "python3-pip"
    "git"
)

for tool in "${REQUIRED_TOOLS[@]}"; do
    if dpkg -l | grep -q "^ii  $tool "; then
        echo -e "${GREEN}[✓]${NC} $tool already installed"
    else
        echo -e "${YELLOW}[+]${NC} Installing $tool..."
        apt install -y "$tool" > /dev/null 2>&1
        echo -e "${GREEN}[✓]${NC} $tool installed"
    fi
done

# Install NetExec
echo -e "\n${BLUE}[*] Installing NetExec...${NC}"
if command -v netexec &> /dev/null; then
    echo -e "${GREEN}[✓]${NC} NetExec already installed"
else
    echo -e "${YELLOW}[+]${NC} Installing NetExec via pipx..."
    apt install -y pipx > /dev/null 2>&1
    pipx ensurepath > /dev/null 2>&1
    pipx install git+https://github.com/Pennyw0rth/NetExec > /dev/null 2>&1
    echo -e "${GREEN}[✓]${NC} NetExec installed"
fi

# Install optional tools
echo -e "\n${BLUE}[*] Installing optional tools (enhanced features)...${NC}"

OPTIONAL_TOOLS=(
    "feroxbuster"
    "ffuf"
    "smbclient"
    "smbmap"
    "ldap-utils"
    "dnsutils"
    "dnsenum"
    "whatweb"
    "enum4linux-ng"
    "nikto"
    "wpscan"
    "testssl.sh"
    "sslscan"
    "nbtscan"
    "onesixtyone"
    "snmp"
    "rpcbind"
    "nfs-common"
    "nuclei"
    "impacket-scripts"
    "sqlmap"
    "joomscan"
    "responder"
    "ssh-audit"
    "sshpass"
    "samba-common-bin"
)

for tool in "${OPTIONAL_TOOLS[@]}"; do
    if dpkg -l | grep -q "^ii  $tool "; then
        echo -e "${GREEN}[✓]${NC} $tool already installed"
    else
        echo -e "${YELLOW}[+]${NC} Installing $tool..."
        apt install -y "$tool" > /dev/null 2>&1 && echo -e "${GREEN}[✓]${NC} $tool installed" || echo -e "${RED}[✗]${NC} $tool installation failed (optional)"
    fi
done

# Install SecLists
echo -e "\n${BLUE}[*] Installing SecLists wordlists...${NC}"
if [ -d "/usr/share/seclists" ]; then
    echo -e "${GREEN}[✓]${NC} SecLists already installed"
else
    echo -e "${YELLOW}[+]${NC} Installing SecLists..."
    apt install -y seclists > /dev/null 2>&1
    echo -e "${GREEN}[✓]${NC} SecLists installed"
fi

# Install Python dependencies
echo -e "\n${BLUE}[*] Installing Python dependencies...${NC}"
pip3 install rich bloodhound --break-system-packages > /dev/null 2>&1
echo -e "${GREEN}[✓]${NC} Python dependencies installed (rich, bloodhound-python)"

# Install Kerbrute (Go binary from GitHub)
echo -e "\n${BLUE}[*] Installing Kerbrute...${NC}"
if command -v kerbrute &> /dev/null; then
    echo -e "${GREEN}[✓]${NC} Kerbrute already installed"
else
    echo -e "${YELLOW}[+]${NC} Downloading Kerbrute..."
    KERBRUTE_URL="https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64"
    if curl -sL "$KERBRUTE_URL" -o /usr/local/bin/kerbrute 2>/dev/null; then
        chmod +x /usr/local/bin/kerbrute
        echo -e "${GREEN}[✓]${NC} Kerbrute installed"
    else
        echo -e "${RED}[✗]${NC} Kerbrute installation failed (optional)"
    fi
fi

# Make script executable
echo -e "\n${BLUE}[*] Setting up HTB Enumeration Tool...${NC}"
chmod +x htb_enum.py
echo -e "${GREEN}[✓]${NC} Script made executable"

# Create symlink (optional)
read -p "$(echo -e ${YELLOW}Create symlink to /usr/local/bin for global access? [y/N]:${NC} )" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ln -sf "$(pwd)/htb_enum.py" /usr/local/bin/htb-enum
    echo -e "${GREEN}[✓]${NC} Symlink created: htb-enum"
    echo -e "${GREEN}[✓]${NC} You can now run the tool from anywhere with: htb-enum"
fi

# Verify installation
echo -e "\n${BLUE}[*] Verifying installation...${NC}"

VERIFICATION_TOOLS=(
    "nmap:nmap"
    "gobuster:gobuster"
    "netexec:netexec"
    "python3:python3"
)

ALL_OK=true
for item in "${VERIFICATION_TOOLS[@]}"; do
    IFS=':' read -r name cmd <<< "$item"
    if command -v "$cmd" &> /dev/null; then
        version=$($cmd --version 2>&1 | head -n1 | cut -d' ' -f2-3)
        echo -e "${GREEN}[✓]${NC} $name: $version"
    else
        echo -e "${RED}[✗]${NC} $name: Not found"
        ALL_OK=false
    fi
done

# Final message
echo -e "\n${BLUE}═══════════════════════════════════════════════════════════${NC}"
if [ "$ALL_OK" = true ]; then
    echo -e "${GREEN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║           Installation Completed Successfully!            ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${GREEN}[✓] All required tools installed${NC}"
    echo -e "${BLUE}[*] You can now run: ./htb_enum.py${NC}"
    
    if [ -L "/usr/local/bin/htb-enum" ]; then
        echo -e "${BLUE}[*] Or globally with: htb-enum${NC}"
    fi
else
    echo -e "${YELLOW}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║      Installation Completed with Some Issues              ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}[!] Some tools failed to install${NC}"
    echo -e "${YELLOW}[!] The tool will still work but with limited features${NC}"
fi

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}\n"

# Show quick start
echo -e "${BLUE}Quick Start:${NC}"
echo -e "  1. Run: ${GREEN}./htb_enum.py -t <target-ip>${NC}"
echo -e "  2. Or: ${GREEN}./htb_enum.py${NC} for interactive mode"
echo -e "  3. Check: ${GREEN}./htb_enum.py --help${NC} for all options\n"

echo -e "${YELLOW}Note:${NC} Some tools may require PATH updates. If netexec is not found,"
echo -e "      run: ${GREEN}source ~/.bashrc${NC} or restart your terminal.\n"

exit 0
