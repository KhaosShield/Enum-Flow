#!/usr/bin/env python3
"""
HTB Enumeration Tool v1.0rc1
Author: @KhaosShield
Description: Comprehensive enumeration tool for HackTheBox labs
"""

import subprocess
import sys
import re
import json
import argparse
import os
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.markdown import Markdown
    from rich.tree import Tree
    from rich import box
except ImportError:
    print("[!] Error: 'rich' library not found. Installing...")
    subprocess.run([sys.executable, "-m", "pip", "install", "rich", "--break-system-packages"], check=True)
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.markdown import Markdown
    from rich.tree import Tree
    from rich import box

console = Console()

# Global configuration
class Config:
    def __init__(self):
        self.target_ip = None
        self.output_dir = None
        self.markdown_report = []
        self.discovered_hosts = []
        self.discovered_ports = {}
        self.credentials = None
        self.stealth_mode = False
        self.threads = 50
        self.scan_depth = 2
        self.start_time = datetime.now()
        
        # Tool paths
        self.tools = {
            'nmap': 'nmap',
            'gobuster': 'gobuster',
            'feroxbuster': 'feroxbuster',
            'ffuf': 'ffuf',
            'netexec': 'netexec',
            'smbclient': 'smbclient',
            'smbmap': 'smbmap',
            'ldapsearch': 'ldapsearch',
            'dig': 'dig',
            'dnsenum': 'dnsenum',
            'wappalyzer': 'wappalyzer',
            'nuclei': 'nuclei',
            'whatweb': 'whatweb',
            'nikto': 'nikto',
            'wpscan': 'wpscan',
            'joomscan': 'joomscan',
            'sqlmap': 'sqlmap',
            'testssl': 'testssl.sh',
            'sslscan': 'sslscan',
            'enum4linux-ng': 'enum4linux-ng',
            'rpcclient': 'rpcclient',
            'snmpwalk': 'snmpwalk',
            'onesixtyone': 'onesixtyone',
            'nbtscan': 'nbtscan',
            'responder': 'responder',
            'impacket': 'impacket-GetNPUsers'
        }
        
        # SecLists paths
        self.wordlists = {
            'dirs_large': '/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt',
            'files_large': '/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt',
            'dirs_common': '/usr/share/seclists/Discovery/Web-Content/common.txt',
            'subdomains': '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt',
            'dns_common': '/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt'
        }

config = Config()

def banner():
    """Display tool banner"""
    banner_text = """
    ╔═══════════════════════════════════════════════════════════╗
    ║               HTB Enumeration Tool v1.0rc1                ║
    ║       Comprehensive Auto Enumeration @KhaosShield         ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner_text, style="bold cyan")

def check_prerequisites():
    """Check if required tools are installed"""
    console.print("\n[bold yellow]Checking Prerequisites...[/bold yellow]")
    
    required_tools = ['nmap', 'gobuster', 'netexec']
    optional_tools = ['feroxbuster', 'ffuf', 'smbclient', 'ldapsearch', 'dig', 'whatweb']
    
    missing_required = []
    missing_optional = []
    
    for tool in required_tools:
        if not tool_exists(tool):
            missing_required.append(tool)
            console.print(f"[red]✗[/red] {tool} - REQUIRED", style="bold")
        else:
            console.print(f"[green]✓[/green] {tool}", style="bold")
    
    for tool in optional_tools:
        if not tool_exists(tool):
            missing_optional.append(tool)
            console.print(f"[yellow]○[/yellow] {tool} - Optional (enhanced features)", style="dim")
        else:
            console.print(f"[green]✓[/green] {tool}", style="bold")
    
    if missing_required:
        console.print(f"\n[red]Error: Missing required tools: {', '.join(missing_required)}[/red]")
        console.print("[yellow]Install with: sudo apt install <tool_name>[/yellow]")
        sys.exit(1)
    
    if missing_optional:
        console.print(f"\n[yellow]Optional tools not found: {', '.join(missing_optional)}[/yellow]")
        console.print("[dim]Some enhanced features may be unavailable[/dim]")
    
    console.print("[green]✓ All required prerequisites met![/green]\n")

def tool_exists(tool):
    """Check if a tool exists in PATH"""
    return subprocess.run(['which', tool], capture_output=True).returncode == 0

def run_command(cmd, description="", timeout=None):
    """Run a shell command and return output"""
    try:
        console.print(f"[cyan]→[/cyan] {description}", style="dim")
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        console.print(f"[red]✗ Command timed out: {description}[/red]")
        return "", "Timeout", -1
    except Exception as e:
        console.print(f"[red]✗ Error running command: {e}[/red]")
        return "", str(e), -1

def save_output(filename, content):
    """Save command output to file"""
    filepath = os.path.join(config.output_dir, filename)
    with open(filepath, 'w') as f:
        f.write(content)
    return filepath

def add_to_report(section, content):
    """Add content to markdown report"""
    config.markdown_report.append(f"\n## {section}\n")
    config.markdown_report.append(content)

def get_target_ip():
    """Prompt user for target IP address"""
    console.print("\n[bold cyan]═══ Target Configuration ═══[/bold cyan]\n")
    
    while True:
        ip = console.input("[bold yellow]Enter target IP address:[/bold yellow] ").strip()
        
        # Basic IP validation
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            octets = ip.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                config.target_ip = ip
                console.print(f"[green]✓[/green] Target set: {ip}\n")
                return ip
        
        console.print("[red]Invalid IP address format. Please try again.[/red]")

def create_output_directory():
    """Create output directory for scan results"""
    dirname = config.target_ip
    config.output_dir = os.path.join(os.getcwd(), dirname)
    
    # Check if directory exists and handle accordingly
    if os.path.exists(config.output_dir):
        response = console.input(f"[yellow]Directory {dirname} already exists. Overwrite? (y/n):[/yellow] ").strip().lower()
        if response != 'y':
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dirname = f"{config.target_ip}_{timestamp}"
            config.output_dir = os.path.join(os.getcwd(), dirname)
            console.print(f"[yellow]Using timestamped directory instead[/yellow]")
    
    os.makedirs(config.output_dir, exist_ok=True)
    console.print(f"[green]✓[/green] Output directory: {config.output_dir}\n")
    
    add_to_report("Scan Information", f"""
- **Target IP:** {config.target_ip}
- **Scan Date:** {config.start_time.strftime("%Y-%m-%d %H:%M:%S")}
- **Output Directory:** {config.output_dir}
""")

def nmap_basic_scan():
    """Run initial Nmap port scan"""
    console.print(Panel.fit(
        "[bold cyan]Phase 1: Initial Port Discovery[/bold cyan]",
        border_style="cyan"
    ))
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Running Nmap port scan...", total=None)
        
        # Fast SYN scan for all ports
        cmd = f"nmap -p- -T4 --min-rate=1000 -Pn {config.target_ip}"
        
        if config.stealth_mode:
            cmd = f"nmap -p- -T2 -Pn {config.target_ip}"
        
        stdout, stderr, code = run_command(cmd, "Initial port discovery", timeout=600)
        progress.update(task, completed=100)
    
    save_output("nmap_initial.txt", stdout)
    
    # Parse open ports
    ports = re.findall(r'(\d+)/tcp\s+open', stdout)
    
    if ports:
        config.discovered_ports = {port: {} for port in ports}
        
        table = Table(title="Discovered Open Ports", box=box.ROUNDED)
        table.add_column("Port", style="cyan", justify="center")
        table.add_column("Count", style="green", justify="center")
        
        table.add_row(", ".join(ports), str(len(ports)))
        console.print(table)
        
        add_to_report("Open Ports Discovery", f"""
**Discovered {len(ports)} open ports:**

```
{', '.join(ports)}
```

**Full Nmap Output:**
```
{stdout[:2000]}...
```
""")
    else:
        console.print("[yellow]No open ports found in initial scan[/yellow]")
    
    return list(config.discovered_ports.keys())

def nmap_detailed_scan(ports):
    """Run detailed Nmap scan on discovered ports"""
    console.print(Panel.fit(
        "[bold cyan]Phase 2: Service & Version Detection[/bold cyan]",
        border_style="cyan"
    ))
    
    port_list = ",".join(ports)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Running detailed service scan...", total=None)
        
        # Detailed scan with scripts and version detection
        cmd = f"nmap -p{port_list} -sV -sC -A -Pn -T4 -oN {config.output_dir}/nmap_detailed.txt {config.target_ip}"
        
        stdout, stderr, code = run_command(cmd, "Detailed port enumeration", timeout=900)
        progress.update(task, completed=100)
    
    save_output("nmap_detailed.txt", stdout)
    
    
    parse_nmap_output(stdout)
    
    
    display_service_table()
    
    add_to_report("Detailed Service Enumeration", f"""
**Service and Version Details:**

```
{stdout[:3000]}...
```
""")

def parse_nmap_output(output):
    """Parse Nmap output for service information and hostnames"""
    lines = output.split('\n')
    current_port = None
    
    for line in lines:
        # Parse port information
        port_match = re.match(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?', line)
        if port_match:
            port = port_match.group(1)
            service = port_match.group(2)
            version = port_match.group(3) if port_match.group(3) else "Unknown"
            
            if port in config.discovered_ports:
                config.discovered_ports[port] = {
                    'service': service,
                    'version': version
                }
                current_port = port
        
        # Look for hostnames
        hostname_match = re.search(r'(\S+\.htb)', line, re.IGNORECASE)
        if hostname_match:
            hostname = hostname_match.group(1)
            if hostname not in config.discovered_hosts:
                config.discovered_hosts.append(hostname)
                console.print(f"[green]✓[/green] Found hostname: [bold]{hostname}[/bold]")

def display_service_table():
    """Display discovered services in a formatted table"""
    if not config.discovered_ports:
        return
    
    table = Table(title="Service Details", box=box.ROUNDED, show_lines=True)
    table.add_column("Port", style="cyan", justify="center", width=8)
    table.add_column("Service", style="yellow", width=15)
    table.add_column("Version", style="green")
    
    for port, info in sorted(config.discovered_ports.items(), key=lambda x: int(x[0])):
        service = info.get('service', 'unknown')
        version = info.get('version', 'Unknown')
        table.add_row(port, service, version)
    
    console.print(table)

def update_hosts_file():
    """Add discovered hostnames to /etc/hosts"""
    if not config.discovered_hosts:
        console.print("[yellow]No hostnames discovered to add to /etc/hosts[/yellow]")
        return
    
    console.print(f"\n[bold yellow]Found {len(config.discovered_hosts)} hostname(s):[/bold yellow]")
    for host in config.discovered_hosts:
        console.print(f"  • {host}")
    
    response = console.input("\n[bold cyan]Add to /etc/hosts? (y/n):[/bold cyan] ").strip().lower()
    
    if response == 'y':
        try:
            # Check current /etc/hosts content
            with open('/etc/hosts', 'r') as f:
                current_hosts = f.read()
            
            # Prepare entry
            host_entry = f"\n# HTB Lab - Added {datetime.now()}\n"
            host_entry += f"{config.target_ip}    {' '.join(config.discovered_hosts)}\n"
            
            # Check if already exists
            if config.target_ip in current_hosts and any(h in current_hosts for h in config.discovered_hosts):
                console.print("[yellow]Entry may already exist in /etc/hosts[/yellow]")
            
            # Write using sudo
            cmd = f"echo '{host_entry}' | sudo tee -a /etc/hosts > /dev/null"
            result = subprocess.run(cmd, shell=True)
            
            if result.returncode == 0:
                console.print("[green]✓ Successfully updated /etc/hosts[/green]")
                add_to_report("Hostname Discovery", f"""
**Discovered Hostnames:**
{chr(10).join(f'- {host}' for host in config.discovered_hosts)}

**Added to /etc/hosts:**
```
{config.target_ip}    {' '.join(config.discovered_hosts)}
```
""")
            else:
                console.print("[red]✗ Failed to update /etc/hosts (permission denied?)[/red]")
        except Exception as e:
            console.print(f"[red]✗ Error updating /etc/hosts: {e}[/red]")

def enumerate_web_directories(port='80'):
    """Enumerate web directories using gobuster"""
    console.print(Panel.fit(
        f"[bold cyan]Phase 3: Web Directory Enumeration (Port {port})[/bold cyan]",
        border_style="cyan"
    ))
    
    # Check wordlist availability
    wordlist = config.wordlists.get('dirs_common')
    if not os.path.exists(wordlist):
        console.print(f"[yellow]Wordlist not found: {wordlist}[/yellow]")
        wordlist = console.input("Enter custom wordlist path (or press Enter to skip): ").strip()
        if not wordlist or not os.path.exists(wordlist):
            console.print("[yellow]Skipping directory enumeration[/yellow]")
            return
    
    # Ask for scan depth
    depth = console.input(f"\n[bold cyan]Enter recursion depth (1-5) [default: 2]:[/bold cyan] ").strip()
    try:
        depth = int(depth) if depth else 2
        depth = max(1, min(5, depth))
    except ValueError:
        depth = 2
    
    config.scan_depth = depth
    console.print(f"[green]✓[/green] Using recursion depth: {depth}\n")
    
    # Determine protocol
    is_https = '443' in config.discovered_ports or 'ssl' in config.discovered_ports.get(port, {}).get('service', '').lower()
    protocol = 'https' if is_https else 'http'
    
    # Check if hostname exists
    target = config.discovered_hosts[0] if config.discovered_hosts else config.target_ip
    base_url = f"{protocol}://{target}:{port}" if port not in ['80', '443'] else f"{protocol}://{target}"
    
    console.print(f"[cyan]Target URL:[/cyan] {base_url}\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning directories...", total=None)
        
        # Gobuster command
        output_file = f"{config.output_dir}/gobuster_port{port}.txt"
        cmd = f"gobuster dir -u {base_url} -w {wordlist} -t {config.threads} -o {output_file} -q -r --no-error"
        
        if depth > 1:
            cmd += f" -d {depth}"
        
        # Add common extensions
        cmd += " -x php,html,txt,asp,aspx,jsp"
        
        stdout, stderr, code = run_command(cmd, f"Gobuster directory scan (depth: {depth})", timeout=1800)
        progress.update(task, completed=100)
    
    # Parse and display results
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            results = f.read()
        
        # Extract found directories
        found_dirs = re.findall(r'(/\S+)\s+\(Status: (\d+)\)', results)
        
        if found_dirs:
            table = Table(title=f"Discovered Directories (Port {port})", box=box.ROUNDED)
            table.add_column("Path", style="cyan")
            table.add_column("Status", style="green", justify="center")
            
            for path, status in found_dirs[:50]:  # Show first 50
                table.add_row(path, status)
            
            console.print(table)
            
            if len(found_dirs) > 50:
                console.print(f"[dim]... and {len(found_dirs) - 50} more (see output file)[/dim]")
            
            add_to_report(f"Web Directory Enumeration (Port {port})", f"""
**Base URL:** {base_url}
**Recursion Depth:** {depth}
**Discovered Paths:** {len(found_dirs)}

**Sample Results:**
```
{results[:2000]}...
```

**Full results:** `{output_file}`
""")
        else:
            console.print("[yellow]No directories found[/yellow]")
    
    # Check for common files
    check_common_files(base_url)

def check_common_files(base_url):
    """Check for common interesting files"""
    console.print("\n[bold cyan]Checking for common files...[/bold cyan]")
    
    common_files = [
        'robots.txt', 'sitemap.xml', '.git/HEAD', '.env', 
        'config.php', 'web.config', '.htaccess', 'phpinfo.php',
        'README.md', 'CHANGELOG.txt', 'backup.zip', 'db.sql'
    ]
    
    found_files = []
    
    for file in common_files:
        url = f"{base_url}/{file}"
        try:
            result = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', url, '-k', '--max-time', '5'],
                capture_output=True,
                text=True
            )
            status = result.stdout.strip()
            
            if status == '200':
                found_files.append((file, status))
                console.print(f"[green]✓[/green] Found: {file} (Status: {status})")
        except:
            pass
    
    if found_files:
        add_to_report("Common Files Discovery", f"""
**Found Files:**
{chr(10).join(f'- `{file}` (Status: {status})' for file, status in found_files)}
""")

def enumerate_vhosts(port='80'):
    """Enumerate virtual hosts and subdomains"""
    console.print(Panel.fit(
        "[bold cyan]Phase 4: Virtual Host & Subdomain Enumeration[/bold cyan]",
        border_style="cyan"
    ))
    
    if not config.discovered_hosts:
        console.print("[yellow]No base hostname discovered. Skipping VHOST enumeration.[/yellow]")
        return
    
    base_domain = config.discovered_hosts[0].split('.', 1)[-1]  # Get base domain
    
    wordlist = config.wordlists.get('subdomains')
    if not os.path.exists(wordlist):
        console.print("[yellow]Subdomain wordlist not found. Skipping.[/yellow]")
        return
    
    # Use ffuf if available, otherwise gobuster
    if tool_exists('ffuf'):
        enumerate_vhosts_ffuf(base_domain, port, wordlist)
    else:
        enumerate_vhosts_gobuster(base_domain, port, wordlist)

def enumerate_vhosts_ffuf(base_domain, port, wordlist):
    """VHOST enumeration using ffuf"""
    protocol = 'https' if port == '443' else 'http'
    base_url = f"{protocol}://{config.target_ip}:{port}" if port not in ['80', '443'] else f"{protocol}://{config.target_ip}"
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Enumerating VHOSTs with ffuf...", total=None)
        
        output_file = f"{config.output_dir}/vhosts_ffuf.txt"
        cmd = f"ffuf -w {wordlist} -u {base_url} -H 'Host: FUZZ.{base_domain}' -mc 200,301,302,403 -t {config.threads} -o {output_file} -of csv -s"
        
        stdout, stderr, code = run_command(cmd, "VHOST enumeration", timeout=600)
        progress.update(task, completed=100)
    
    # Parse results
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                lines = f.readlines()
            
            if len(lines) > 1:  # Has results beyond header
                found_vhosts = []
                for line in lines[1:]:  # Skip header
                    parts = line.split(',')
                    if len(parts) >= 1:
                        vhost = f"{parts[0]}.{base_domain}"
                        found_vhosts.append(vhost)
                        console.print(f"[green]✓[/green] Found VHOST: {vhost}")
                
                if found_vhosts:
                    add_to_report("Virtual Host Discovery", f"""
**Discovered VHOSTs:**
{chr(10).join(f'- {vhost}' for vhost in found_vhosts)}

**Note:** Add these to /etc/hosts pointing to {config.target_ip}
""")
        except Exception as e:
            console.print(f"[yellow]Could not parse VHOST results: {e}[/yellow]")

def enumerate_vhosts_gobuster(base_domain, port, wordlist):
    """VHOST enumeration using gobuster"""
    protocol = 'https' if port == '443' else 'http'
    base_url = f"{protocol}://{config.target_ip}:{port}" if port not in ['80', '443'] else f"{protocol}://{config.target_ip}"
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Enumerating VHOSTs with gobuster...", total=None)
        
        output_file = f"{config.output_dir}/vhosts_gobuster.txt"
        cmd = f"gobuster vhost -u {base_url} -w {wordlist} --domain {base_domain} -t {config.threads} -o {output_file} -q"
        
        stdout, stderr, code = run_command(cmd, "VHOST enumeration", timeout=600)
        progress.update(task, completed=100)

def enumerate_dns():
    """Enumerate DNS if port 53 is open"""
    if '53' not in config.discovered_ports:
        return
    
    console.print(Panel.fit(
        "[bold cyan]Phase 5: DNS Enumeration[/bold cyan]",
        border_style="cyan"
    ))
    
    if not config.discovered_hosts:
        console.print("[yellow]No hostname found. Skipping DNS enumeration.[/yellow]")
        return
    
    domain = config.discovered_hosts[0].split('.', 1)[-1]
    
    # Zone transfer attempt
    console.print(f"[cyan]Attempting DNS zone transfer for {domain}...[/cyan]")
    cmd = f"dig axfr @{config.target_ip} {domain}"
    stdout, stderr, code = run_command(cmd, "DNS zone transfer")
    
    if "Transfer failed" not in stdout and len(stdout) > 100:
        console.print("[green]✓ Zone transfer successful![/green]")
        save_output("dns_zone_transfer.txt", stdout)
        add_to_report("DNS Zone Transfer", f"""
**Success! Zone transfer allowed for {domain}**

```
{stdout[:2000]}...
```
""")
    else:
        console.print("[yellow]Zone transfer not allowed[/yellow]")
    
    # DNS enumeration with dnsenum
    if tool_exists('dnsenum'):
        console.print(f"[cyan]Running dnsenum on {domain}...[/cyan]")
        output_file = f"{config.output_dir}/dnsenum.txt"
        cmd = f"dnsenum --dnsserver {config.target_ip} --enum {domain} -o {output_file}"
        run_command(cmd, "DNS enumeration", timeout=300)

def analyze_ssl_certificates():
    """Extract information from SSL certificates"""
    ssl_ports = ['443', '8443', '9443']
    
    for port in ssl_ports:
        if port in config.discovered_ports:
            console.print(f"\n[cyan]Analyzing SSL certificate on port {port}...[/cyan]")
            
            target = config.discovered_hosts[0] if config.discovered_hosts else config.target_ip
            cmd = f"echo | openssl s_client -connect {target}:{port} -showcerts 2>/dev/null | openssl x509 -noout -text"
            
            stdout, stderr, code = run_command(cmd, f"SSL certificate analysis (port {port})")
            
            if stdout:
                # Extract Subject Alternative Names
                san_match = re.search(r'Subject Alternative Name:(.*?)(?=\n\s{12}[A-Z]|\n\n|\Z)', stdout, re.DOTALL)
                if san_match:
                    sans = san_match.group(1)
                    alt_names = re.findall(r'DNS:([^\s,]+)', sans)
                    
                    if alt_names:
                        console.print(f"[green]✓[/green] Found alternative names in certificate:")
                        for name in alt_names:
                            console.print(f"  • {name}")
                            if name not in config.discovered_hosts:
                                config.discovered_hosts.append(name)
                
                save_output(f"ssl_cert_port{port}.txt", stdout)

def enumerate_smb():
    """Enumerate SMB shares and users"""
    if '445' not in config.discovered_ports and '139' not in config.discovered_ports:
        return
    
    console.print(Panel.fit(
        "[bold cyan]Phase 6: SMB Enumeration[/bold cyan]",
        border_style="cyan"
    ))
    
    # Null session check
    console.print("[cyan]Checking for null session...[/cyan]")
    cmd = f"smbclient -N -L //{config.target_ip}"
    stdout, stderr, code = run_command(cmd, "SMB null session check")
    
    if "Sharename" in stdout:
        console.print("[green]✓ Null session allowed![/green]")
        save_output("smb_null_session.txt", stdout)
        
        # Parse shares
        shares = re.findall(r'^\s+(\S+)\s+Disk', stdout, re.MULTILINE)
        if shares:
            console.print(f"[green]Found {len(shares)} shares:[/green]")
            for share in shares:
                console.print(f"  • {share}")
    else:
        console.print("[yellow]Null session not allowed[/yellow]")
    
    # Enum4linux
    if tool_exists('enum4linux'):
        console.print("[cyan]Running enum4linux...[/cyan]")
        output_file = f"{config.output_dir}/enum4linux.txt"
        cmd = f"enum4linux -a {config.target_ip} > {output_file}"
        run_command(cmd, "enum4linux enumeration", timeout=300)

def check_active_directory():
    """Check if target appears to be Active Directory"""
    ad_indicators = ['88', '389', '636', '3268', '3269']  # Kerberos, LDAP, Global Catalog
    
    ad_ports_found = [port for port in ad_indicators if port in config.discovered_ports]
    
    if len(ad_ports_found) >= 2:
        console.print(Panel.fit(
            "[bold yellow]Active Directory Detected![/bold yellow]",
            border_style="yellow"
        ))
        
        console.print("\n[bold cyan]This appears to be an Active Directory environment[/bold cyan]")
        console.print(f"[green]AD-related ports found: {', '.join(ad_ports_found)}[/green]\n")
        
        return True
    
    return False

def enumerate_active_directory():
    """Enumerate Active Directory with NetExec"""
    if not check_active_directory():
        return
    
    console.print(Panel.fit(
        "[bold cyan]Phase 7: Active Directory Enumeration[/bold cyan]",
        border_style="cyan"
    ))
    
    # Ask for credentials
    has_creds = console.input("\n[bold cyan]Do you have credentials? (y/n):[/bold cyan] ").strip().lower()
    
    username = None
    password = None
    domain = None
    
    if has_creds == 'y':
        domain = console.input("[bold yellow]Domain (or press Enter for default):[/bold yellow] ").strip()
        username = console.input("[bold yellow]Username:[/bold yellow] ").strip()
        password = console.input("[bold yellow]Password:[/bold yellow] ").strip()
        
        if domain:
            config.credentials = f"{domain}/{username}:{password}"
        else:
            config.credentials = f"{username}:{password}"
    
    if not tool_exists('netexec'):
        console.print("[red]NetExec not found. Install from: https://github.com/Pennyw0rth/NetExec[/red]")
        return
    
    # SMB Enumeration with NetExec
    if '445' in config.discovered_ports or '139' in config.discovered_ports:
        console.print("\n[bold cyan]SMB Enumeration with NetExec[/bold cyan]")
        
        # Basic SMB check
        cmd = f"netexec smb {config.target_ip}"
        stdout, stderr, code = run_command(cmd, "NetExec SMB discovery")
        save_output("netexec_smb_discovery.txt", stdout)
        
        if username and password:
            # Authenticated enumeration
            auth_cmd = f"netexec smb {config.target_ip} -u '{username}' -p '{password}'"
            if domain:
                auth_cmd += f" -d '{domain}'"
            
            console.print("[cyan]Testing credentials...[/cyan]")
            stdout, stderr, code = run_command(auth_cmd, "NetExec credential test")
            
            if "Pwn3d!" in stdout or "+" in stdout:
                console.print("[green]✓ Credentials valid![/green]")
                
                # Enumerate shares
                cmd = f"{auth_cmd} --shares"
                stdout, stderr, code = run_command(cmd, "Enumerating SMB shares")
                save_output("netexec_shares.txt", stdout)
                
                # Enumerate users
                cmd = f"{auth_cmd} --users"
                stdout, stderr, code = run_command(cmd, "Enumerating users")
                save_output("netexec_users.txt", stdout)
                
                # Enumerate groups
                cmd = f"{auth_cmd} --groups"
                stdout, stderr, code = run_command(cmd, "Enumerating groups")
                save_output("netexec_groups.txt", stdout)
                
                # Password policy
                cmd = f"{auth_cmd} --pass-pol"
                stdout, stderr, code = run_command(cmd, "Getting password policy")
                save_output("netexec_passpol.txt", stdout)
            else:
                console.print("[red]✗ Credentials invalid[/red]")
        else:
            # Unauthenticated enumeration
            console.print("[cyan]Attempting unauthenticated enumeration...[/cyan]")
            
            # Check for null sessions
            cmd = f"netexec smb {config.target_ip} -u '' -p ''"
            stdout, stderr, code = run_command(cmd, "Null session check")
            save_output("netexec_null_session.txt", stdout)
            
            # Guest access
            cmd = f"netexec smb {config.target_ip} -u 'guest' -p ''"
            stdout, stderr, code = run_command(cmd, "Guest session check")
            save_output("netexec_guest_session.txt", stdout)
    
    # LDAP Enumeration
    if '389' in config.discovered_ports or '636' in config.discovered_ports:
        console.print("\n[bold cyan]LDAP Enumeration[/bold cyan]")
        
        # Anonymous bind check
        cmd = f"ldapsearch -x -H ldap://{config.target_ip} -s base namingcontexts"
        stdout, stderr, code = run_command(cmd, "LDAP anonymous bind")
        
        if stdout and "namingContexts" in stdout:
            console.print("[green]✓ Anonymous LDAP bind successful[/green]")
            save_output("ldap_anonymous.txt", stdout)
            
            # Extract naming contexts
            contexts = re.findall(r'namingContexts: (.+)', stdout)
            if contexts:
                console.print(f"[green]Found naming contexts:[/green]")
                for ctx in contexts:
                    console.print(f"  • {ctx}")
                    
                    # Dump LDAP with naming context
                    cmd = f"ldapsearch -x -H ldap://{config.target_ip} -b '{ctx}'"
                    stdout_dump, stderr, code = run_command(cmd, f"LDAP dump: {ctx}", timeout=300)
                    if stdout_dump:
                        save_output(f"ldap_dump_{ctx.replace(',', '_').replace('=', '_')}.txt", stdout_dump)
        else:
            console.print("[yellow]Anonymous LDAP bind not allowed[/yellow]")
    
    # Kerberos (AS-REP Roasting)
    if '88' in config.discovered_ports:
        console.print("\n[bold cyan]Kerberos Enumeration[/bold cyan]")
        
        if tool_exists('kerbrute'):
            console.print("[cyan]User enumeration with kerbrute...[/cyan]")
            
            # Need a user list
            userlist = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
            if os.path.exists(userlist):
                domain_name = domain if domain else "htb.local"
                cmd = f"kerbrute userenum --dc {config.target_ip} -d {domain_name} {userlist}"
                stdout, stderr, code = run_command(cmd, "Kerbrute user enumeration", timeout=300)
                save_output("kerbrute_users.txt", stdout)
        
        # AS-REP Roasting with NetExec
        if username:
            console.print("[cyan]Attempting AS-REP roasting...[/cyan]")
            cmd = f"netexec ldap {config.target_ip} -u '{username}' -p '{password}' --asreproast asrep_hashes.txt"
            if domain:
                cmd += f" -d '{domain}'"
            
            stdout, stderr, code = run_command(cmd, "AS-REP roasting")
            
            if os.path.exists("asrep_hashes.txt"):
                console.print("[green]✓ AS-REP roastable accounts found![/green]")
                import shutil
                shutil.move("asrep_hashes.txt", f"{config.output_dir}/asrep_hashes.txt")

def enumerate_additional_services():
    """Enumerate other discovered services"""
    console.print(Panel.fit(
        "[bold cyan]Phase 8: Additional Service Enumeration[/bold cyan]",
        border_style="cyan"
    ))
    
    for port, info in config.discovered_ports.items():
        service = info.get('service', '').lower()
        
        # FTP
        if service == 'ftp':
            console.print(f"\n[cyan]Enumerating FTP (port {port})...[/cyan]")
            
            # Anonymous login
            cmd = f"ftp -n {config.target_ip} {port} <<EOF\nuser anonymous anonymous\nls\nbye\nEOF"
            stdout, stderr, code = run_command(cmd, "FTP anonymous login")
            
            if "230" in stdout or "Login successful" in stdout:
                console.print("[green]✓ Anonymous FTP login allowed[/green]")
                save_output(f"ftp_port{port}.txt", stdout)
        
        # SSH
        elif service == 'ssh':
            console.print(f"\n[cyan]Analyzing SSH (port {port})...[/cyan]")
            cmd = f"ssh-audit {config.target_ip} -p {port}"
            if tool_exists('ssh-audit'):
                stdout, stderr, code = run_command(cmd, "SSH audit")
                save_output(f"ssh_audit_port{port}.txt", stdout)
        
        # MySQL
        elif 'mysql' in service:
            console.print(f"\n[cyan]Enumerating MySQL (port {port})...[/cyan]")
            cmd = f"nmap -p {port} --script mysql-info,mysql-enum {config.target_ip}"
            stdout, stderr, code = run_command(cmd, "MySQL enumeration")
            save_output(f"mysql_port{port}.txt", stdout)
        
        # MSSQL
        elif 'ms-sql' in service or 'mssql' in service:
            console.print(f"\n[cyan]Enumerating MSSQL (port {port})...[/cyan]")
            cmd = f"nmap -p {port} --script ms-sql-info,ms-sql-ntlm-info {config.target_ip}"
            stdout, stderr, code = run_command(cmd, "MSSQL enumeration")
            save_output(f"mssql_port{port}.txt", stdout)
        
        # RDP
        elif service == 'ms-wbt-server' or 'rdp' in service:
            console.print(f"\n[cyan]Analyzing RDP (port {port})...[/cyan]")
            cmd = f"nmap -p {port} --script rdp-enum-encryption,rdp-vuln-ms12-020 {config.target_ip}"
            stdout, stderr, code = run_command(cmd, "RDP analysis")
            save_output(f"rdp_port{port}.txt", stdout)
        
        # SNMP
        elif service == 'snmp':
            console.print(f"\n[cyan]Enumerating SNMP (port {port})...[/cyan]")
            
            if tool_exists('snmpwalk'):
                cmd = f"snmpwalk -v2c -c public {config.target_ip}"
                stdout, stderr, code = run_command(cmd, "SNMP walk (public)", timeout=120)
                
                if "Timeout" not in stderr and stdout:
                    console.print("[green]✓ SNMP enumeration successful[/green]")
                    save_output(f"snmp_port{port}.txt", stdout)

def web_technology_detection():
    """Detect web technologies using whatweb"""
    if '80' not in config.discovered_ports and '443' not in config.discovered_ports:
        return
    
    if not tool_exists('whatweb'):
        return
    
    console.print("\n[bold cyan]Detecting Web Technologies...[/bold cyan]")
    
    for port in ['80', '443', '8080', '8443']:
        if port in config.discovered_ports:
            protocol = 'https' if port in ['443', '8443'] else 'http'
            target = config.discovered_hosts[0] if config.discovered_hosts else config.target_ip
            url = f"{protocol}://{target}:{port}" if port not in ['80', '443'] else f"{protocol}://{target}"
            
            cmd = f"whatweb -a 3 {url}"
            stdout, stderr, code = run_command(cmd, f"Technology detection: {url}")
            
            if stdout:
                console.print(f"\n[green]Technologies on {url}:[/green]")
                console.print(stdout[:500])
                save_output(f"whatweb_port{port}.txt", stdout)

def nikto_scan():
    """Run Nikto web vulnerability scanner"""
    if '80' not in config.discovered_ports and '443' not in config.discovered_ports:
        return
    
    if not tool_exists('nikto'):
        return
    
    console.print("\n[bold cyan]Running Nikto Web Vulnerability Scanner...[/bold cyan]")
    
    for port in ['80', '443', '8080', '8443']:
        if port in config.discovered_ports:
            protocol = 'https' if port in ['443', '8443'] else 'http'
            target = config.discovered_hosts[0] if config.discovered_hosts else config.target_ip
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(f"[cyan]Nikto scan on port {port}...", total=None)
                
                output_file = f"{config.output_dir}/nikto_port{port}.txt"
                cmd = f"nikto -h {protocol}://{target}:{port} -output {output_file} -Format txt"
                
                stdout, stderr, code = run_command(cmd, f"Nikto scan: {protocol}://{target}:{port}", timeout=600)
                progress.update(task, completed=100)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    results = f.read()
                    if "0 host(s) tested" not in results:
                        console.print(f"[green]✓[/green] Nikto found potential issues on port {port}")
                        console.print(f"[dim]Results saved to: {output_file}[/dim]")

def cms_detection():
    """Detect and enumerate CMS (WordPress, Joomla, Drupal)"""
    if '80' not in config.discovered_ports and '443' not in config.discovered_ports:
        return
    
    console.print("\n[bold cyan]CMS Detection & Enumeration...[/bold cyan]")
    
    for port in ['80', '443', '8080', '8443']:
        if port in config.discovered_ports:
            protocol = 'https' if port in ['443', '8443'] else 'http'
            target = config.discovered_hosts[0] if config.discovered_hosts else config.target_ip
            url = f"{protocol}://{target}:{port}" if port not in ['80', '443'] else f"{protocol}://{target}"
            
            # Check for WordPress
            console.print(f"[cyan]Checking for WordPress on {url}...[/cyan]")
            cmd = f"curl -s {url}/wp-login.php -k -L -I | grep -i 'wp-'"
            stdout, stderr, code = run_command(cmd, "WordPress detection")
            
            if stdout or "wp-" in stderr:
                console.print(f"[green]✓[/green] WordPress detected!")
                
                # Run WPScan if available
                if tool_exists('wpscan'):
                    console.print("[cyan]Running WPScan...[/cyan]")
                    output_file = f"{config.output_dir}/wpscan_port{port}.txt"
                    cmd = f"wpscan --url {url} --enumerate vp,vt,u --plugins-detection aggressive -o {output_file}"
                    
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console
                    ) as progress:
                        task = progress.add_task("[cyan]WPScan enumeration...", total=None)
                        stdout, stderr, code = run_command(cmd, "WPScan", timeout=900)
                        progress.update(task, completed=100)
                    
                    if os.path.exists(output_file):
                        console.print(f"[green]✓[/green] WPScan complete: {output_file}")
            
            # Check for Joomla
            console.print(f"[cyan]Checking for Joomla on {url}...[/cyan]")
            cmd = f"curl -s {url}/administrator/manifests/files/joomla.xml -k -L | grep -i 'joomla'"
            stdout, stderr, code = run_command(cmd, "Joomla detection")
            
            if stdout or "joomla" in stderr.lower():
                console.print(f"[green]✓[/green] Joomla detected!")
                
                # Run JoomScan if available
                if tool_exists('joomscan'):
                    console.print("[cyan]Running JoomScan...[/cyan]")
                    output_file = f"{config.output_dir}/joomscan_port{port}.txt"
                    cmd = f"joomscan -u {url} > {output_file}"
                    stdout, stderr, code = run_command(cmd, "JoomScan", timeout=600)
                    
                    if os.path.exists(output_file):
                        console.print(f"[green]✓[/green] JoomScan complete: {output_file}")
            
            # Check for Drupal
            console.print(f"[cyan]Checking for Drupal on {url}...[/cyan]")
            cmd = f"curl -s {url}/CHANGELOG.txt -k -L | grep -i 'drupal'"
            stdout, stderr, code = run_command(cmd, "Drupal detection")
            
            if stdout or "drupal" in stderr.lower():
                console.print(f"[green]✓[/green] Drupal detected!")

def ssl_vulnerability_scan():
    """Deep SSL/TLS vulnerability scanning"""
    ssl_ports = ['443', '8443', '9443', '3389']
    
    has_ssl = any(port in config.discovered_ports for port in ssl_ports)
    if not has_ssl:
        return
    
    console.print("\n[bold cyan]SSL/TLS Vulnerability Scanning...[/bold cyan]")
    
    # TestSSL.sh scan
    if tool_exists('testssl.sh') or tool_exists('testssl'):
        for port in ssl_ports:
            if port in config.discovered_ports:
                target = config.discovered_hosts[0] if config.discovered_hosts else config.target_ip
                
                console.print(f"[cyan]Running testssl.sh on {target}:{port}...[/cyan]")
                output_file = f"{config.output_dir}/testssl_port{port}.txt"
                
                testssl_cmd = 'testssl.sh' if tool_exists('testssl.sh') else 'testssl'
                cmd = f"{testssl_cmd} --quiet --jsonfile {output_file}.json {target}:{port} > {output_file}"
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    task = progress.add_task(f"[cyan]SSL/TLS scan on port {port}...", total=None)
                    stdout, stderr, code = run_command(cmd, f"TestSSL scan: {target}:{port}", timeout=300)
                    progress.update(task, completed=100)
                
                if os.path.exists(output_file):
                    console.print(f"[green]✓[/green] SSL scan complete: {output_file}")
    
    # SSLScan as alternative/complement
    elif tool_exists('sslscan'):
        for port in ssl_ports:
            if port in config.discovered_ports:
                target = config.discovered_hosts[0] if config.discovered_hosts else config.target_ip
                
                console.print(f"[cyan]Running sslscan on {target}:{port}...[/cyan]")
                output_file = f"{config.output_dir}/sslscan_port{port}.txt"
                cmd = f"sslscan --no-colour {target}:{port} > {output_file}"
                
                stdout, stderr, code = run_command(cmd, f"SSLScan: {target}:{port}")
                
                if os.path.exists(output_file):
                    console.print(f"[green]✓[/green] SSL scan complete: {output_file}")

def nfs_enumeration():
    """Enumerate NFS shares if port 2049 is open"""
    if '2049' not in config.discovered_ports:
        return
    
    console.print("\n[bold cyan]NFS Enumeration...[/bold cyan]")
    
    # Show NFS exports
    console.print("[cyan]Checking NFS exports...[/cyan]")
    cmd = f"showmount -e {config.target_ip}"
    stdout, stderr, code = run_command(cmd, "NFS showmount")
    
    if stdout and "Export list" in stdout:
        console.print("[green]✓[/green] NFS exports found:")
        console.print(stdout)
        save_output("nfs_exports.txt", stdout)
        
        # Parse and try to mount
        exports = re.findall(r'^(/\S+)', stdout, re.MULTILINE)
        if exports:
            console.print(f"\n[yellow]Found {len(exports)} NFS export(s). Consider mounting:[/yellow]")
            for export in exports:
                console.print(f"  sudo mount -t nfs {config.target_ip}:{export} /mnt/nfs")
    else:
        console.print("[yellow]No NFS exports found or access denied[/yellow]")
    
    # Nmap NFS scripts
    cmd = f"nmap -p 2049 --script nfs-* {config.target_ip}"
    stdout, stderr, code = run_command(cmd, "Nmap NFS scripts")
    save_output("nfs_nmap_scripts.txt", stdout)

def snmp_enumeration():
    """Enhanced SNMP enumeration"""
    if '161' not in config.discovered_ports:
        return
    
    console.print("\n[bold cyan]SNMP Enumeration...[/bold cyan]")
    
    common_communities = ['public', 'private', 'community', 'manager']
    
    # Try onesixtyone for faster community string discovery
    if tool_exists('onesixtyone'):
        console.print("[cyan]Brute-forcing SNMP community strings...[/cyan]")
        
        # Create temporary community list
        comm_file = f"{config.output_dir}/snmp_communities.txt"
        with open(comm_file, 'w') as f:
            f.write('\n'.join(common_communities))
        
        cmd = f"onesixtyone -c {comm_file} {config.target_ip}"
        stdout, stderr, code = run_command(cmd, "onesixtyone community brute-force")
        
        if stdout:
            found_communities = re.findall(r'\[(\w+)\]', stdout)
            if found_communities:
                console.print(f"[green]✓[/green] Found SNMP communities: {', '.join(found_communities)}")
                save_output("snmp_communities_found.txt", stdout)
                
                # Walk with found communities
                for community in found_communities:
                    console.print(f"[cyan]Walking SNMP with community '{community}'...[/cyan]")
                    cmd = f"snmpwalk -v2c -c {community} {config.target_ip} > {config.output_dir}/snmpwalk_{community}.txt"
                    stdout, stderr, code = run_command(cmd, f"SNMP walk: {community}", timeout=180)
    
    # Try default communities with snmpwalk
    else:
        for community in common_communities:
            console.print(f"[cyan]Trying SNMP community '{community}'...[/cyan]")
            cmd = f"snmpwalk -v2c -c {community} {config.target_ip}"
            stdout, stderr, code = run_command(cmd, f"SNMP walk: {community}", timeout=120)
            
            if stdout and "Timeout" not in stderr and len(stdout) > 100:
                console.print(f"[green]✓[/green] SNMP community '{community}' works!")
                save_output(f"snmpwalk_{community}.txt", stdout)
                break

def netbios_enumeration():
    """Enumerate NetBIOS information"""
    if '137' not in config.discovered_ports and '139' not in config.discovered_ports:
        return
    
    console.print("\n[bold cyan]NetBIOS Enumeration...[/bold cyan]")
    
    # nbtscan
    if tool_exists('nbtscan'):
        console.print("[cyan]Running nbtscan...[/cyan]")
        cmd = f"nbtscan -r {config.target_ip}/32"
        stdout, stderr, code = run_command(cmd, "nbtscan")
        
        if stdout:
            console.print(stdout)
            save_output("nbtscan.txt", stdout)
    
    # nmblookup
    console.print("[cyan]Running nmblookup...[/cyan]")
    cmd = f"nmblookup -A {config.target_ip}"
    stdout, stderr, code = run_command(cmd, "nmblookup")
    
    if stdout:
        save_output("nmblookup.txt", stdout)

def rpc_enumeration():
    """Enumerate RPC services"""
    if '111' not in config.discovered_ports and '135' not in config.discovered_ports:
        return
    
    console.print("\n[bold cyan]RPC Enumeration...[/bold cyan]")
    
    # rpcinfo
    console.print("[cyan]Running rpcinfo...[/cyan]")
    cmd = f"rpcinfo -p {config.target_ip}"
    stdout, stderr, code = run_command(cmd, "rpcinfo")
    
    if stdout and "program" in stdout.lower():
        console.print("[green]✓[/green] RPC services found:")
        console.print(stdout[:500])
        save_output("rpcinfo.txt", stdout)
    
    # rpcclient for Windows
    if '445' in config.discovered_ports and tool_exists('rpcclient'):
        console.print("[cyan]Attempting RPC null session...[/cyan]")
        
        # Try various null session commands
        commands = [
            "enumdomusers",
            "enumdomgroups",
            "querydominfo",
            "lsaenumsid"
        ]
        
        results = []
        for cmd_name in commands:
            cmd = f"rpcclient -U '' -N {config.target_ip} -c '{cmd_name}'"
            stdout, stderr, code = run_command(cmd, f"rpcclient {cmd_name}")
            
            if stdout and "NT_STATUS" not in stdout:
                results.append(f"\n### {cmd_name}\n{stdout}")
                console.print(f"[green]✓[/green] {cmd_name} succeeded")
        
        if results:
            save_output("rpcclient_null_session.txt", '\n'.join(results))

def vulnerability_scanning():
    """Run vulnerability scanning with Nuclei"""
    if not tool_exists('nuclei'):
        return
    
    console.print("\n[bold cyan]Vulnerability Scanning with Nuclei...[/bold cyan]")
    
    # Check if we have web services
    web_ports = ['80', '443', '8080', '8443']
    has_web = any(port in config.discovered_ports for port in web_ports)
    
    if has_web:
        target = config.discovered_hosts[0] if config.discovered_hosts else config.target_ip
        
        response = console.input("\n[yellow]Run Nuclei vulnerability scan? This may take a while (y/n):[/yellow] ").strip().lower()
        
        if response == 'y':
            # Create target list
            target_file = f"{config.output_dir}/nuclei_targets.txt"
            with open(target_file, 'w') as f:
                for port in web_ports:
                    if port in config.discovered_ports:
                        protocol = 'https' if port in ['443', '8443'] else 'http'
                        url = f"{protocol}://{target}:{port}" if port not in ['80', '443'] else f"{protocol}://{target}"
                        f.write(f"{url}\n")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Running Nuclei...", total=None)
                
                output_file = f"{config.output_dir}/nuclei_results.txt"
                cmd = f"nuclei -l {target_file} -severity critical,high,medium -o {output_file}"
                
                stdout, stderr, code = run_command(cmd, "Nuclei vulnerability scan", timeout=1800)
                progress.update(task, completed=100)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    results = f.read()
                    if results:
                        console.print(f"[green]✓[/green] Nuclei found vulnerabilities!")
                        console.print(f"[yellow]Check: {output_file}[/yellow]")
                    else:
                        console.print("[yellow]No vulnerabilities found[/yellow]")

def impacket_enumeration():
    """Use Impacket tools for additional enumeration"""
    if not ('445' in config.discovered_ports or '88' in config.discovered_ports):
        return
    
    console.print("\n[bold cyan]Impacket Enumeration...[/bold cyan]")
    
    # GetNPUsers for AS-REP roasting without credentials
    if '88' in config.discovered_ports and tool_exists('impacket-GetNPUsers'):
        console.print("[cyan]Attempting AS-REP roasting (no auth)...[/cyan]")
        
        domain = config.discovered_hosts[0].split('.')[-2:] if config.discovered_hosts else 'htb.local'
        domain = '.'.join(domain) if isinstance(domain, list) else domain
        
        # Try with common usernames
        usernames = ['administrator', 'guest', 'admin', 'user', 'svc-admin']
        
        output_file = f"{config.output_dir}/asreproast_nousers.txt"
        cmd = f"impacket-GetNPUsers {domain}/ -dc-ip {config.target_ip} -request -format hashcat -outputfile {output_file}"
        
        stdout, stderr, code = run_command(cmd, "AS-REP roast attempt", timeout=60)
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            console.print("[green]✓[/green] AS-REP roastable accounts found!")
            console.print(f"[yellow]Hashes saved to: {output_file}[/yellow]")

def generate_markdown_report():
    """Generate final markdown report"""
    console.print("\n[bold cyan]Generating Final Report...[/bold cyan]")
    
    # Calculate scan duration
    end_time = datetime.now()
    duration = end_time - config.start_time
    
    # Build report header
    report = f"""# HTB Enumeration Report

## Scan Summary

- **Target IP:** {config.target_ip}
- **Start Time:** {config.start_time.strftime("%Y-%m-%d %H:%M:%S")}
- **End Time:** {end_time.strftime("%Y-%m-%d %H:%M:%S")}
- **Duration:** {duration}
- **Output Directory:** {config.output_dir}

---

"""
    
    # Add all collected sections
    report += "\n".join(config.markdown_report)
    
    # Add summary
    report += f"""

---

## Summary Statistics

- **Open Ports:** {len(config.discovered_ports)}
- **Discovered Hostnames:** {len(config.discovered_hosts)}
- **Services Enumerated:** {len([s for s in config.discovered_ports.values() if s.get('service')])}

## Discovered Hostnames

"""
    
    if config.discovered_hosts:
        report += "\n".join(f"- `{host}`" for host in config.discovered_hosts)
    else:
        report += "*No hostnames discovered*"
    
    report += """

## Next Steps

Based on the enumeration, consider:

1. **Web Applications:** Test for common vulnerabilities (SQLi, XSS, LFI, etc.)
2. **Credentials:** Attempt password spraying, AS-REP roasting, Kerberoasting
3. **Shares:** Explore accessible SMB/NFS shares for sensitive data
4. **Version Exploits:** Search for known CVEs affecting discovered service versions
5. **Privilege Escalation:** Enumerate for misconfigurations once foothold is gained

---

*Report generated by HTB Enumeration Tool v1.0*
"""
    
    # Save report
    report_path = os.path.join(config.output_dir, "enumeration_report.md")
    with open(report_path, 'w') as f:
        f.write(report)
    
    console.print(f"[green]✓ Report saved to: {report_path}[/green]")
    
    return report_path

def main():
    """Main execution flow"""
    parser = argparse.ArgumentParser(
        description="HTB Enumeration Tool v1.0rc1",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-t', '--target', help='Target IP address')
    parser.add_argument('-s', '--stealth', action='store_true', help='Use stealth mode (slower, quieter)')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--quick', action='store_true', help='Quick scan (skip deep enumeration)')
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Check prerequisites
    check_prerequisites()
    
    # Configuration
    if args.target:
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', args.target):
            console.print("[red]Invalid IP address format[/red]")
            sys.exit(1)
        config.target_ip = args.target
    else:
        get_target_ip()
    
    config.stealth_mode = args.stealth
    config.threads = args.threads
    
    if config.stealth_mode:
        console.print("[yellow]⚠ Stealth mode enabled - scans will be slower[/yellow]")
    
    # Create output directory
    create_output_directory()
    
    try:
        # Phase 1: Initial port discovery
        open_ports = nmap_basic_scan()
        
        if not open_ports:
            console.print("[red]No open ports found. Exiting.[/red]")
            sys.exit(0)
        
        # Phase 2: Detailed service enumeration
        nmap_detailed_scan(open_ports)
        
        # Phase 3: Update hosts file if needed
        if config.discovered_hosts:
            update_hosts_file()
        
        # Phase 4: SSL certificate analysis
        analyze_ssl_certificates()
        
        # Phase 5: Web enumeration
        if '80' in config.discovered_ports or '443' in config.discovered_ports:
            for port in ['80', '443', '8080', '8443']:
                if port in config.discovered_ports:
                    enumerate_web_directories(port)
            
            enumerate_vhosts()
            web_technology_detection()
        
        # Phase 6: DNS enumeration
        enumerate_dns()
        
        # Phase 7: Active Directory enumeration
        enumerate_active_directory()
        
        # Phase 8: SMB enumeration
        enumerate_smb()
        
        # Phase 9: Additional services
        if not args.quick:
            enumerate_additional_services()
        
        # Phase 10: Advanced Web Enumeration
        if '80' in config.discovered_ports or '443' in config.discovered_ports:
            if not args.quick:
                console.print(Panel.fit(
                    "[bold cyan]Phase 10: Advanced Web Enumeration[/bold cyan]",
                    border_style="cyan"
                ))
                nikto_scan()
                cms_detection()
                ssl_vulnerability_scan()
                vulnerability_scanning()
        
        # Phase 11: Protocol-Specific Deep Enumeration
        if not args.quick:
            console.print(Panel.fit(
                "[bold cyan]Phase 11: Protocol-Specific Deep Enumeration[/bold cyan]",
                border_style="cyan"
            ))
            nfs_enumeration()
            snmp_enumeration()
            netbios_enumeration()
            rpc_enumeration()
            impacket_enumeration()
        
        # Generate final report
        report_path = generate_markdown_report()
        
        # Final summary
        console.print(Panel.fit(
            f"""[bold green]Enumeration Complete![/bold green]

[cyan]Results saved to:[/cyan] {config.output_dir}
[cyan]Report available at:[/cyan] {report_path}

[yellow]Total time:[/yellow] {datetime.now() - config.start_time}
""",
            border_style="green",
            title="✓ Success"
        ))
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        console.print(f"[cyan]Partial results saved to:[/cyan] {config.output_dir}")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
