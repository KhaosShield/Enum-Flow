#!/usr/bin/env python3
"""
HTB Enumeration Tool v1.0rc2
Author: @KhaosShield
Description: Comprehensive enumeration tool for HackTheBox labs and Pro Labs
"""

import subprocess
import sys
import re
import argparse
import os
from datetime import datetime
import signal
import shutil
import glob
import time

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich import box
except ImportError:
    print("[!] Error: 'rich' library not found. Installing...")
    subprocess.run([sys.executable, "-m", "pip", "install", "rich", "--break-system-packages"], check=True)
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
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
        self.ad_username = None
        self.ad_password = None
        self.ad_domain = None
        self.stealth_mode = False
        self.threads = 50
        self.scan_depth = 2
        self.start_time = datetime.now()
        self.skip_current = False
        self.commands_run = []  # Track all commands executed
        self.phase_skipped = False  # Track if current phase was skipped
        self.skip_requested = False  # Flag for Ctrl+Z skip request
        self.live_hosts = []  # Live hosts discovered in network range
        self.is_range_scan = False  # Flag for network range scanning
        self.depth_prompted = False  # Only ask for recursion depth once
        self.dashboard_enabled = False
        self.no_browser = False
        
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

def handle_skip_signal(signum, frame):
    """Handle SIGTSTP (Ctrl+Z) to skip phase - we'll remap Ctrl+Z behavior"""
    config.skip_requested = True
    console.print("\n[yellow]⊘ Skip requested - finishing current command then moving to next phase...[/yellow]")

def run_phase(phase_func, phase_name, *args, **kwargs):
    """Execute a phase with skip capability"""
    config.skip_requested = False
    config.phase_skipped = False

    emit_event('phase_start', {'phase': phase_name, 'target': config.target_ip})

    try:
        result = phase_func(*args, **kwargs)

        # Check if phase was skipped
        if config.skip_requested or config.phase_skipped:
            console.print(f"[yellow]⊘ Skipped {phase_name}[/yellow]\n")
            add_to_report(phase_name, "**Status:** Skipped by user\n", found_items=0)
            config.skip_requested = False  # Reset for next phase
            emit_event('phase_complete', {'phase': phase_name, 'skipped': True})
            return None

        emit_event('phase_complete', {'phase': phase_name, 'skipped': False})
        return result
    except KeyboardInterrupt:
        # Ctrl+C exits entire script
        raise
    except Exception as e:
        console.print(f"[red]Error in {phase_name}: {e}[/red]")
        emit_event('phase_complete', {'phase': phase_name, 'skipped': False})
        return None


import web as _web
_web.init(config)
from web import emit_event, start_dashboard, generate_html_report


def banner():
    """Display tool banner"""
    banner_text = """
    ╔═══════════════════════════════════════════════════════════╗
    ║         HTB Enumeration Tool v1.0                         ║
    ║         Comprehensive Lab Enumeration Suite               ║
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

def shell_quote(s):
    """Escape a string for safe use inside single quotes in shell commands"""
    if not s:
        return s
    return s.replace("'", "'\\''")

def escape_braces(s):
    """Escape curly braces in a string for safe embedding in f-strings"""
    if not s:
        return s
    return s.replace('{', '{{').replace('}', '}}')

def tool_exists(tool):
    """Check if a tool exists in PATH"""
    return subprocess.run(['which', tool], capture_output=True).returncode == 0

def run_command(cmd, description="", timeout=None, show_command=True):
    """Run a shell command and return output with progress tracking and Ctrl+Z skip support"""
    try:
        # Log the command
        command_entry = {
            'command': cmd,
            'description': description,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        config.commands_run.append(command_entry)
        emit_event('cmd_run', {'description': description, 'command': cmd})

        # Show what we're running
        if show_command:
            console.print(f"\n[bold cyan]Running:[/bold cyan] [dim]{description}[/dim]")
            console.print(f"[bold]Command:[/bold] [yellow]{cmd}[/yellow]")
        else:
            console.print(f"[cyan]→[/cyan] {description}", style="dim")
        
        # Check if skip was already requested
        if config.skip_requested:
            console.print("[yellow]Skipping due to user request...[/yellow]")
            config.phase_skipped = True
            return "", "Skipped", -2
        
        # Run command as subprocess so we can monitor for Ctrl+Z
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Poll process while checking for skip request
        import time
        start_time = time.time()
        while process.poll() is None:
            # Check for skip request
            if config.skip_requested:
                console.print("\n[yellow]⊘ Skipping - terminating current command...[/yellow]")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except Exception:
                    process.kill()
                config.phase_skipped = True
                return "", "Skipped by user", -2
            
            # Check for timeout
            if timeout and (time.time() - start_time) > timeout:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except Exception:
                    process.kill()
                console.print(f"[red]✗ Command timed out: {description}[/red]")
                return "", "Timeout", -1
            
            time.sleep(0.1)  # Check every 100ms
        
        stdout, stderr = process.communicate()
        return stdout, stderr, process.returncode
        
    except KeyboardInterrupt:
        # Ctrl+C exits entire script
        if 'process' in locals():
            process.terminate()
        raise
    except Exception as e:
        console.print(f"[red]✗ Error running command: {e}[/red]")
        return "", str(e), -1

def prompt_user(message):
    """Wrap console.input() with SSE notifications so the browser shows an alert."""
    emit_event('prompt_waiting', {'message': message})
    try:
        result = console.input(message)
    finally:
        emit_event('prompt_resolved', {})
    return result


def save_output(filename, content, command=None):
    """Save command output to file with command header"""
    filepath = os.path.join(config.output_dir, filename)
    
    # Prepare output with command header
    output_content = ""
    
    if command:
        output_content += "=" * 80 + "\n"
        output_content += "COMMAND EXECUTED\n"
        output_content += "=" * 80 + "\n"
        output_content += f"Command: {command}\n"
        output_content += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        output_content += f"Target: {config.target_ip}\n"
        output_content += "=" * 80 + "\n\n"
    
    output_content += content
    
    with open(filepath, 'w') as f:
        f.write(output_content)
    return filepath

def add_to_report(section, content, commands=None, found_items=None):
    """Add content to markdown report with command tracking"""
    config.markdown_report.append(f"\n## {section}\n")
    
    # Add commands if provided
    if commands:
        config.markdown_report.append("### Commands Executed\n\n")
        if isinstance(commands, list):
            for cmd in commands:
                config.markdown_report.append(f"```bash\n{cmd}\n```\n")
        else:
            config.markdown_report.append(f"```bash\n{commands}\n```\n")
        config.markdown_report.append("\n")
    
    # Add findings
    if found_items is not None and found_items == 0:
        config.markdown_report.append("### Results\n\n")
        config.markdown_report.append("**Status:** Nothing found\n\n")
    
    config.markdown_report.append(content)
    emit_event('finding', {'section': section, 'content': content[:2000]})

def validate_target(target):
    """Validate target IP, CIDR notation, or range"""
    target = target.strip()

    # Single IP: 10.10.110.1
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
        octets = target.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True

    # CIDR notation: 10.10.110.0/24
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', target):
        ip_part, cidr = target.rsplit('/', 1)
        octets = ip_part.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets) and 0 <= int(cidr) <= 32:
            return True

    # Range notation: 10.10.110.1-254
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$', target):
        ip_part, end = target.rsplit('-', 1)
        octets = ip_part.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets) and 0 <= int(end) <= 255:
            return True

    return False

def is_network_range(target):
    """Check if target is a CIDR or range (not a single IP)"""
    return '/' in target or re.match(r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$', target)

def discover_live_hosts():
    """Discover live hosts in a network range using ping sweep"""
    console.print(Panel.fit(
        "[bold cyan]Phase 0: Host Discovery[/bold cyan]",
        border_style="cyan"
    ))

    cmd = f"nmap -sn -T4 {config.target_ip}"

    console.print(f"\n[bold]Command:[/bold] [yellow]{cmd}[/yellow]")
    console.print("[dim]Discovering live hosts in network range. [bold yellow]Press Ctrl+Z to skip.[/bold yellow][/dim]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning for live hosts...", total=100)

        stdout, stderr, code = run_command(cmd, "Host discovery", timeout=300, show_command=False)
        progress.update(task, completed=100)

    save_output("host_discovery.txt", stdout, command=cmd)

    # Parse discovered hosts
    live_hosts = re.findall(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', stdout)

    if live_hosts:
        # Store in config for later use
        config.live_hosts = live_hosts

        table = Table(title="Discovered Live Hosts", box=box.ROUNDED)
        table.add_column("#", style="dim", justify="center", width=4)
        table.add_column("IP Address", style="cyan")
        table.add_column("Status", style="green")

        for idx, host in enumerate(live_hosts, 1):
            table.add_row(str(idx), host, "Up")

        console.print(table)
        console.print(f"\n[green]✓[/green] Found [bold]{len(live_hosts)}[/bold] live host(s)\n")

        host_table = '\n'.join(f'| {i+1} | {h} |' for i, h in enumerate(live_hosts))
        add_to_report("Phase 0: Host Discovery", f"""
**Network Range:** {config.target_ip}
**Live Hosts Found:** {len(live_hosts)}

| # | IP Address |
|---|------------|
{host_table}

""", commands=cmd, found_items=len(live_hosts))

        return live_hosts
    else:
        console.print("[yellow]No live hosts discovered in range[/yellow]")
        add_to_report("Phase 0: Host Discovery",
                     f"**Status:** No live hosts found in {config.target_ip}\n",
                     commands=cmd,
                     found_items=0)
        return []

def get_target_ip():
    """Prompt user for target IP address, CIDR, or range"""
    console.print("\n[bold cyan]═══ Target Configuration ═══[/bold cyan]\n")
    console.print("[dim]Supported formats: 10.10.110.1 | 10.10.110.0/24 | 10.10.110.1-254[/dim]\n")

    while True:
        ip = prompt_user("[bold yellow]Enter target:[/bold yellow] ").strip()

        if validate_target(ip):
            config.target_ip = ip
            console.print(f"[green]✓[/green] Target set: {ip}\n")
            return ip

        console.print("[red]Invalid target format. Please try again.[/red]")

def create_output_directory():
    """Create output directory for scan results"""
    # Sanitize target for directory name (replace / with _ for CIDR notation)
    dirname = config.target_ip.replace('/', '_')
    config.output_dir = os.path.join(os.getcwd(), dirname)

    # Check if directory exists and handle accordingly
    if os.path.exists(config.output_dir):
        response = prompt_user(f"[yellow]Directory {dirname} already exists. Overwrite? (y/n):[/yellow] ").strip().lower()
        if response != 'y':
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dirname = f"{dirname}_{timestamp}"
            config.output_dir = os.path.join(os.getcwd(), dirname)
            console.print(f"[yellow]Using timestamped directory instead[/yellow]")
    
    os.makedirs(config.output_dir, exist_ok=True)
    console.print(f"[green]✓[/green] Output directory: {config.output_dir}\n")
    
    add_to_report("Scan Information", f"""
- **Target IP:** {config.target_ip}
- **Scan Date:** {config.start_time.strftime("%Y-%m-%d %H:%M:%S")}
- **Output Directory:** {config.output_dir}
""")

def update_output_directory_with_hostname():
    """Rename output directory to use hostname instead of IP"""
    if not config.discovered_hosts:
        return
    
    # Get first hostname and extract machine name (before first dot)
    full_hostname = config.discovered_hosts[0]
    machine_name = full_hostname.split('.')[0].lower()
    
    # New directory name
    new_dirname = machine_name
    new_output_dir = os.path.join(os.getcwd(), new_dirname)
    
    # Check if new name would conflict
    if os.path.exists(new_output_dir) and new_output_dir != config.output_dir:
        console.print(f"[yellow]Directory '{new_dirname}' already exists, keeping IP-based name[/yellow]")
        return
    
    # Rename directory
    try:
        old_dir = config.output_dir
        os.rename(config.output_dir, new_output_dir)
        config.output_dir = new_output_dir
        console.print(f"[green]✓[/green] Renamed output directory: [cyan]{old_dir}[/cyan] → [cyan]{new_output_dir}[/cyan]\n")
    except Exception as e:
        console.print(f"[yellow]Could not rename directory: {e}[/yellow]")

def nmap_basic_scan():
    """Run initial Nmap port scan"""
    console.print(Panel.fit(
        "[bold cyan]Phase 1: Initial Port Discovery[/bold cyan]",
        border_style="cyan"
    ))
    
    # Fast SYN scan for all ports
    cmd = f"nmap -p- -T4 --min-rate=1000 -Pn {config.target_ip}"
    
    if config.stealth_mode:
        cmd = f"nmap -p- -T2 -Pn {config.target_ip}"
    
    # Run the scan
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning all 65535 ports...", total=100)
        
        # Show the command
        console.print(f"\n[bold]Command:[/bold] [yellow]{cmd}[/yellow]")
        console.print("[dim]This may take 5-10 minutes. [bold yellow]Press Ctrl+Z to skip this phase.[/bold yellow][/dim]\n")
        
        stdout, stderr, code = run_command(cmd, "Initial port discovery", timeout=600, show_command=False)
        progress.update(task, completed=100)
    
    save_output("nmap_initial.txt", stdout, command=cmd)
    
    # Parse open ports
    ports = re.findall(r'(\d+)/tcp\s+open', stdout)
    
    if ports:
        config.discovered_ports = {port: {} for port in ports}
        
        table = Table(title="Discovered Open Ports", box=box.ROUNDED)
        table.add_column("Port", style="cyan", justify="center")
        table.add_column("Count", style="green", justify="center")
        
        table.add_row(", ".join(ports), str(len(ports)))
        console.print(table)
        
        add_to_report("Phase 1: Initial Port Discovery", f"""
**Discovered {len(ports)} open ports:**

```
{', '.join(ports)}
```

**Full Nmap Output:**
```
{escape_braces(stdout[:2000])}...
```
""", commands=cmd, found_items=len(ports))
    else:
        console.print("[yellow]No open ports found in initial scan[/yellow]")
        add_to_report("Phase 1: Initial Port Discovery", 
                     "**Status:** No open ports discovered\n", 
                     commands=cmd, 
                     found_items=0)
    
    return list(config.discovered_ports.keys())

def nmap_detailed_scan(ports):
    """Run detailed Nmap scan on discovered ports"""
    console.print(Panel.fit(
        "[bold cyan]Phase 2: Service & Version Detection[/bold cyan]",
        border_style="cyan"
    ))
    
    port_list = ",".join(ports)
    
    cmd = f"nmap -p{port_list} -sV -sC -A -Pn -T4 -oN {config.output_dir}/nmap_detailed.txt {config.target_ip}"
    console.print(f"\n[bold]Command:[/bold] [yellow]{cmd}[/yellow]")
    console.print("[dim]Running detailed service scan. [bold yellow]Press Ctrl+Z to skip this phase.[/bold yellow][/dim]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning services on discovered ports...", total=100)
        
        stdout, stderr, code = run_command(cmd, "Detailed port enumeration", timeout=900, show_command=False)
        progress.update(task, completed=100)
    
    save_output("nmap_detailed.txt", stdout)
    
    # Parse service information
    parse_nmap_output(stdout)
    
    # Display results
    display_service_table()
    
    add_to_report("Detailed Service Enumeration", f"""
**Service and Version Details:**

```
{escape_braces(stdout[:3000])}...
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
                emit_event('port_found', {'port': port, 'service': service, 'version': version})
        
        # Look for hostnames
        hostname_match = re.search(r'(\S+\.htb)', line, re.IGNORECASE)
        if hostname_match:
            hostname = hostname_match.group(1)
            if hostname not in config.discovered_hosts:
                config.discovered_hosts.append(hostname)
                emit_event('host_found', {'hostname': hostname})
                console.print(f"[green]✓[/green] Found hostname: [bold]{hostname}[/bold]")
                
                # Rename output directory to use hostname (only on first discovery)
                if len(config.discovered_hosts) == 1:
                    update_output_directory_with_hostname()

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
    
    response = prompt_user("\n[bold cyan]Add to /etc/hosts? (y/n):[/bold cyan] ").strip().lower()
    
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
                host_list = '\n'.join(f'- {host}' for host in config.discovered_hosts)
                add_to_report("Hostname Discovery", f"""
**Discovered Hostnames:**
{host_list}

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
        wordlist = prompt_user("Enter custom wordlist path (or press Enter to skip): ").strip()
        if not wordlist or not os.path.exists(wordlist):
            console.print("[yellow]Skipping directory enumeration[/yellow]")
            return
    
    # Ask for scan depth only once across all hosts
    if not config.depth_prompted:
        depth = prompt_user(f"\n[bold cyan]Enter recursion depth (1-5) [default: 2]:[/bold cyan] ").strip()
        try:
            depth = int(depth) if depth else 2
            depth = max(1, min(5, depth))
        except ValueError:
            depth = 2
        config.scan_depth = depth
        config.depth_prompted = True
        console.print(f"[green]✓[/green] Using recursion depth: {depth}\n")
    else:
        depth = config.scan_depth
        console.print(f"[green]✓[/green] Using recursion depth: {depth}\n")
    
    # Determine protocol
    is_https = '443' in config.discovered_ports or 'ssl' in config.discovered_ports.get(port, {}).get('service', '').lower()
    protocol = 'https' if is_https else 'http'
    
    # Check if hostname exists
    target = config.discovered_hosts[0] if config.discovered_hosts else config.target_ip
    base_url = f"{protocol}://{target}:{port}" if port not in ['80', '443'] else f"{protocol}://{target}"
    
    console.print(f"[cyan]Target URL:[/cyan] {base_url}\n")
    
    # Gobuster command
    output_file = f"{config.output_dir}/gobuster_port{port}.txt"
    # Remove -q flag to show progress, keep output to file
    cmd = f"gobuster dir -u {base_url} -w {wordlist} -t {config.threads} -o {output_file} -r --no-error"
    
    if depth > 1:
        cmd += f" -d {depth}"
    
    # Add common extensions
    cmd += " -x php,html,txt,asp,aspx,jsp"
    
    console.print(f"\n[bold]Command:[/bold] [yellow]{cmd}[/yellow]")
    console.print(f"[dim]Scanning {wordlist}. [bold yellow]Press Ctrl+Z to skip this phase.[/bold yellow][/dim]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task(f"[cyan]Scanning directories (depth: {depth})...", total=100)
        
        stdout, stderr, code = run_command(cmd, f"Gobuster directory scan", timeout=1800, show_command=False)
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
{escape_braces(results[:2000])}...
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
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            console.print(f"[dim]Warning checking {file}: {e}[/dim]")
    
    if found_files:
        file_list = '\n'.join(f'- `{file}` (Status: {status})' for file, status in found_files)
        add_to_report("Common Files Discovery", f"""
**Found Files:**
{file_list}
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
                    vhost_list = '\n'.join(f'- {vhost}' for vhost in found_vhosts)
                    add_to_report("Virtual Host Discovery", f"""
**Discovered VHOSTs:**
{vhost_list}

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
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Enumerating VHOSTs with gobuster...", total=100)

        output_file = f"{config.output_dir}/vhosts_gobuster.txt"
        cmd = f"gobuster vhost -u {base_url} -w {wordlist} --domain {base_domain} -t {config.threads} -o {output_file} -q"

        stdout, stderr, code = run_command(cmd, "VHOST enumeration", timeout=600, show_command=False)
        progress.update(task, completed=100)

    # Parse results
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                lines = f.readlines()

            if lines:
                found_vhosts = []
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    # Gobuster vhost output format: "Found: sub.domain.com Status: 200 [Size: 1234]"
                    match = re.match(r'Found:\s+(\S+)', line)
                    if match:
                        vhost = match.group(1)
                        found_vhosts.append(vhost)
                        console.print(f"[green]✓[/green] Found VHOST: {vhost}")

                if found_vhosts:
                    vhost_list = '\n'.join(f'- {vhost}' for vhost in found_vhosts)
                    add_to_report("Virtual Host Discovery", f"""
**Discovered VHOSTs (gobuster):**
{vhost_list}

**Note:** Add these to /etc/hosts pointing to {config.target_ip}
""")
        except Exception as e:
            console.print(f"[yellow]Could not parse VHOST results: {e}[/yellow]")

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
{escape_braces(stdout[:2000])}...
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
                                
                                # Rename directory if this is first hostname discovered
                                if len(config.discovered_hosts) == 1:
                                    update_output_directory_with_hostname()
                
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
    
    # Enum4linux - stream output directly to terminal
    if tool_exists('enum4linux'):
        output_file = f"{config.output_dir}/enum4linux.txt"
        enum4linux_cmd = f"enum4linux -a {config.target_ip}"
        console.print(f"\n[bold]Command:[/bold] [yellow]{enum4linux_cmd}[/yellow]")
        console.print("[dim]Output streams live below. [bold yellow]Press Ctrl+Z to skip.[/bold yellow][/dim]\n")

        config.commands_run.append({
            'command': enum4linux_cmd,
            'description': 'enum4linux enumeration',
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        # Stream output to terminal via tee, saving to file simultaneously
        tee_cmd = f"{enum4linux_cmd} 2>&1 | tee '{output_file}'"
        process = subprocess.Popen(
            tee_cmd,
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=None,
            stderr=None
        )

        import time
        start_time = time.time()
        timed_out = False
        while process.poll() is None:
            if config.skip_requested:
                console.print("\n[yellow]Skipping enum4linux...[/yellow]")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except Exception:
                    process.kill()
                break
            if time.time() - start_time > 600:
                console.print("\n[yellow]enum4linux timed out after 10 minutes[/yellow]")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except Exception:
                    process.kill()
                timed_out = True
                break
            time.sleep(0.5)

        # Parse saved output for report
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                stdout = f.read()

            if timed_out:
                console.print("[dim]Partial results captured before timeout[/dim]")

            # Summary of key findings
            users = re.findall(r'user:\[([^\]]+)\]', stdout)
            shares_found = re.findall(r'^\s+([\w\$]+)\s+Disk', stdout, re.MULTILINE)
            groups = re.findall(r'group:\[([^\]]+)\]', stdout)

            if users or shares_found or groups:
                console.print(f"\n[bold cyan]enum4linux Summary:[/bold cyan]")
                if users:
                    console.print(f"  [green]Users: {len(users)}[/green]")
                if shares_found:
                    console.print(f"  [green]Shares: {len(shares_found)}[/green]")
                if groups:
                    console.print(f"  [green]Groups: {len(groups)}[/green]")

            console.print(f"  [dim]Full output: {output_file}[/dim]")

            # Add to report
            enum4linux_report = ""
            if users:
                user_list = '\n'.join(f'- {u}' for u in users)
                enum4linux_report += f"**Users ({len(users)}):**\n{user_list}\n\n"
            if shares_found:
                share_list = '\n'.join(f'- {s}' for s in shares_found)
                enum4linux_report += f"**Shares ({len(shares_found)}):**\n{share_list}\n\n"
            if groups:
                group_list = '\n'.join(f'- {g}' for g in groups)
                enum4linux_report += f"**Groups ({len(groups)}):**\n{group_list}\n\n"
            if enum4linux_report:
                add_to_report("enum4linux Enumeration", enum4linux_report, commands=enum4linux_cmd)

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
    has_creds = prompt_user("\n[bold cyan]Do you have credentials? (y/n):[/bold cyan] ").strip().lower()
    
    username = None
    password = None
    domain = None
    
    if has_creds == 'y':
        domain = shell_quote(prompt_user("[bold yellow]Domain (or press Enter for default):[/bold yellow] ").strip())
        username = shell_quote(prompt_user("[bold yellow]Username:[/bold yellow] ").strip())
        password = shell_quote(prompt_user("[bold yellow]Password:[/bold yellow] ").strip())

        # Store credentials for reuse across all AD sub-phases
        config.ad_username = username
        config.ad_password = password
        config.ad_domain = domain

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
        console.print("[dim]Enumerating SMB services. [bold yellow]Press Ctrl+Z to skip.[/bold yellow][/dim]\n")

        # Basic SMB check
        cmd = f"netexec smb {config.target_ip}"
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Discovering SMB services...", total=100)
            stdout, stderr, code = run_command(cmd, "NetExec SMB discovery", show_command=False)
            progress.update(task, completed=100)

        # Check for netexec DB schema errors
        if "Schema mismatch" in stdout or "Schema mismatch" in stderr:
            console.print("[bold red]NetExec database schema error detected![/bold red]")
            console.print("[yellow]Fix: rm -f ~/.nxc/workspaces/default/smb.db[/yellow]")
            console.print("[dim]Then re-run the scan. NetExec will rebuild the database.[/dim]")
            save_output("netexec_smb_discovery.txt", stdout)
            return

        save_output("netexec_smb_discovery.txt", stdout)

        if username and password:
            # Authenticated enumeration
            auth_cmd = f"netexec smb {config.target_ip} -u '{username}' -p '{password}'"
            if domain:
                auth_cmd += f" -d '{domain}'"

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Testing credentials via SMB...", total=100)
                stdout, stderr, code = run_command(auth_cmd, "NetExec credential test", show_command=False)
                progress.update(task, completed=100)

            creds_valid = "Pwn3d!" in stdout or "[+]" in stdout
            ldap_only = False

            # LDAP fallback if SMB auth failed (useful for service accounts like svc-alfresco)
            if not creds_valid and ('389' in config.discovered_ports or '636' in config.discovered_ports):
                console.print("[yellow]SMB auth failed, trying LDAP fallback...[/yellow]")
                ldap_auth_cmd = f"netexec ldap {config.target_ip} -u '{username}' -p '{password}'"
                if domain:
                    ldap_auth_cmd += f" -d '{domain}'"
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console
                ) as progress:
                    task = progress.add_task("[cyan]Testing credentials via LDAP...", total=100)
                    stdout_ldap, stderr_ldap, code_ldap = run_command(ldap_auth_cmd, "NetExec LDAP credential test", show_command=False)
                    progress.update(task, completed=100)
                if "[+]" in stdout_ldap:
                    creds_valid = True
                    ldap_only = True
                    console.print("[green]✓ Credentials valid via LDAP![/green]")

            if creds_valid:
                if not ldap_only:
                    console.print("[green]✓ Credentials valid![/green]")

                # Build protocol-appropriate base command
                enum_cmd = auth_cmd if not ldap_only else ldap_auth_cmd

                # Enumerate shares (SMB only - not supported via LDAP)
                if not ldap_only:
                    cmd = f"{enum_cmd} --shares"
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        console=console
                    ) as progress:
                        task = progress.add_task("[cyan]Enumerating SMB shares...", total=100)
                        stdout, stderr, code = run_command(cmd, "Enumerating SMB shares", show_command=False)
                        progress.update(task, completed=100)
                    save_output("netexec_shares.txt", stdout)

                # Enumerate users
                cmd = f"{enum_cmd} --users"
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console
                ) as progress:
                    task = progress.add_task("[cyan]Enumerating domain users...", total=100)
                    stdout, stderr, code = run_command(cmd, "Enumerating users", show_command=False)
                    progress.update(task, completed=100)
                save_output("netexec_users.txt", stdout)

                # Enumerate groups
                cmd = f"{enum_cmd} --groups"
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console
                ) as progress:
                    task = progress.add_task("[cyan]Enumerating domain groups...", total=100)
                    stdout, stderr, code = run_command(cmd, "Enumerating groups", show_command=False)
                    progress.update(task, completed=100)
                save_output("netexec_groups.txt", stdout)

                # Password policy (SMB only - not supported via LDAP)
                if not ldap_only:
                    cmd = f"{enum_cmd} --pass-pol"
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        console=console
                    ) as progress:
                        task = progress.add_task("[cyan]Getting password policy...", total=100)
                        stdout, stderr, code = run_command(cmd, "Getting password policy", show_command=False)
                        progress.update(task, completed=100)
                    save_output("netexec_passpol.txt", stdout)
            else:
                console.print("[red]✗ Credentials invalid[/red]")
        else:
            # Unauthenticated enumeration
            console.print("[cyan]Attempting unauthenticated enumeration...[/cyan]")

            # Check for null sessions
            cmd = f"netexec smb {config.target_ip} -u '' -p ''"
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Checking null sessions...", total=100)
                stdout, stderr, code = run_command(cmd, "Null session check", show_command=False)
                progress.update(task, completed=100)
            save_output("netexec_null_session.txt", stdout)

            # Guest access
            cmd = f"netexec smb {config.target_ip} -u 'guest' -p ''"
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Checking guest access...", total=100)
                stdout, stderr, code = run_command(cmd, "Guest session check", show_command=False)
                progress.update(task, completed=100)
            save_output("netexec_guest_session.txt", stdout)
    
    # LDAP Enumeration
    if '389' in config.discovered_ports or '636' in config.discovered_ports:
        console.print("\n[bold cyan]LDAP Enumeration[/bold cyan]")
        console.print("[dim]Enumerating LDAP services. [bold yellow]Press Ctrl+Z to skip.[/bold yellow][/dim]\n")

        # Anonymous bind check
        cmd = f"ldapsearch -x -H ldap://{config.target_ip} -s base namingcontexts"
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Checking anonymous LDAP bind...", total=100)
            stdout, stderr, code = run_command(cmd, "LDAP anonymous bind", show_command=False)
            progress.update(task, completed=100)

        if stdout and "namingContexts" in stdout:
            console.print("[green]✓ Anonymous LDAP bind successful[/green]")
            save_output("ldap_anonymous.txt", stdout)

            # Extract naming contexts
            contexts = re.findall(r'namingContexts: (.+)', stdout)
            if contexts:
                console.print(f"[green]Found naming contexts:[/green]")
                for ctx in contexts:
                    console.print(f"  • {ctx}")

                    # Dump LDAP with naming context (limited to 1000 entries, 30s server timeout)
                    cmd = f"ldapsearch -x -H ldap://{config.target_ip} -b '{ctx}' -z 1000 -l 30"
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        console=console
                    ) as progress:
                        task = progress.add_task(f"[cyan]Dumping LDAP: {ctx}...", total=100)
                        stdout_dump, stderr, code = run_command(cmd, f"LDAP dump: {ctx}", timeout=120, show_command=False)
                        progress.update(task, completed=100)
                    if stdout_dump:
                        entry_count = len(re.findall(r'^dn: ', stdout_dump, re.MULTILINE))
                        console.print(f"[green]✓ LDAP dump complete: {entry_count} entries[/green]")
                        save_output(f"ldap_dump_{ctx.replace(',', '_').replace('=', '_')}.txt", stdout_dump)
        else:
            console.print("[yellow]Anonymous LDAP bind not allowed[/yellow]")
    
    # Kerberos (AS-REP Roasting)
    if '88' in config.discovered_ports:
        console.print("\n[bold cyan]Kerberos Enumeration[/bold cyan]")
        console.print("[dim]Enumerating Kerberos services. [bold yellow]Press Ctrl+Z to skip.[/bold yellow][/dim]\n")

        if tool_exists('kerbrute'):
            # Need a user list
            userlist = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
            if os.path.exists(userlist):
                domain_name = domain if domain else "htb.local"
                cmd = f"kerbrute userenum --dc {config.target_ip} -d {domain_name} {userlist}"
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console
                ) as progress:
                    task = progress.add_task("[cyan]Enumerating users with kerbrute...", total=100)
                    stdout, stderr, code = run_command(cmd, "Kerbrute user enumeration", timeout=300, show_command=False)
                    progress.update(task, completed=100)
                save_output("kerbrute_users.txt", stdout)

        # AS-REP Roasting with NetExec
        if username:
            asrep_file = os.path.join(config.output_dir, "asrep_hashes.txt")
            cmd = f"netexec ldap {config.target_ip} -u '{username}' -p '{password}' --asreproast '{asrep_file}'"
            if domain:
                cmd += f" -d '{domain}'"

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Attempting AS-REP roasting...", total=100)
                stdout, stderr, code = run_command(cmd, "AS-REP roasting", show_command=False)
                progress.update(task, completed=100)

            if os.path.exists(asrep_file):
                console.print("[green]✓ AS-REP roastable accounts found![/green]")
        else:
            # Try AS-REP roasting without credentials
            enumerate_ad_asreproast_noauth()
    
    # Enhanced AD enumeration (only if credentials provided)
    if username and password:
        # Test credentials across all services
        test_credentials_everywhere()
        
        # BloodHound collection
        enumerate_ad_bloodhound()
        
        # Kerberoasting
        enumerate_ad_kerberoasting()
        
        # Deep share enumeration
        enumerate_ad_shares_deep()
        
        # GPP password extraction
        enumerate_ad_gpp()

# ============================================================================
# ACTIVE DIRECTORY ADVANCED ENUMERATION
# ============================================================================

def enumerate_ad_bloodhound():
    """Run BloodHound data collection"""
    console.print("\n[bold cyan]═══ BloodHound Collection ═══[/bold cyan]")
    
    if not tool_exists('bloodhound-python'):
        console.print("[yellow]bloodhound-python not found. Install: pip install bloodhound[/yellow]")
        console.print("[dim]Skipping BloodHound collection[/dim]")
        return
    
    run_bh = prompt_user("[bold yellow]Run BloodHound collection? (y/n):[/bold yellow] ").strip().lower()
    if run_bh != 'y':
        return

    username = config.ad_username
    password = config.ad_password
    domain = config.ad_domain

    if not all([username, password, domain]):
        console.print("[red]All fields required for BloodHound (username, password, domain)[/red]")
        return
    
    console.print(f"\n[bold]Command:[/bold] [yellow]bloodhound-python -d {domain} -u {username} -p [REDACTED] -dc {config.target_ip} -c All --zip[/yellow]")
    console.print("[dim]Collecting AD data. [bold yellow]Press Ctrl+Z to skip this phase.[/bold yellow][/dim]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Collecting AD objects...", total=100)
        
        cmd = f"bloodhound-python -d {domain} -u {username} -p '{password}' -dc {config.target_ip} -c All --zip"
        stdout, stderr, code = run_command(cmd, "BloodHound collection", timeout=600, show_command=False)
        progress.update(task, completed=100)
    
    # Move BloodHound output files to output directory
    json_files = glob.glob("*_bloodhound.json") + glob.glob("*_users.json") + glob.glob("*_groups.json") + glob.glob("*_computers.json") + glob.glob("*_domains.json")
    zip_files = glob.glob("*bloodhound*.zip")
    
    moved_files = []
    for f in json_files + zip_files:
        try:
            dest = os.path.join(config.output_dir, f)
            shutil.move(f, dest)
            moved_files.append(f)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not move {f}: {e}[/yellow]")
    
    if moved_files:
        console.print(f"\n[green]✓ BloodHound data collected![/green]")
        for f in moved_files:
            console.print(f"  • {f}")
        console.print(f"\n[yellow]💡 Next Steps:[/yellow]")
        console.print(f"   1. Open BloodHound GUI")
        console.print(f"   2. Import: {config.output_dir}/*.json or .zip")
        console.print(f"   3. Search for attack paths to Domain Admins")
    else:
        console.print("[yellow]No BloodHound data generated[/yellow]")

def enumerate_ad_kerberoasting():
    """Attempt Kerberoasting to find service accounts"""
    console.print("\n[bold cyan]═══ Kerberoasting ═══[/bold cyan]")

    username = config.ad_username
    password = config.ad_password
    domain = config.ad_domain

    if not all([username, password, domain]):
        console.print("[dim]Skipping Kerberoasting (requires username, password, and domain)[/dim]")
        return
    
    kerberoast_found = False
    
    # Method 1: NetExec (preferred)
    if tool_exists('netexec'):
        console.print("[cyan]Attempting Kerberoasting with NetExec...[/cyan]")
        
        kerb_file = os.path.join(config.output_dir, "kerberoast_hashes.txt")
        cmd = f"netexec ldap {config.target_ip} -u '{username}' -p '{password}' -d '{domain}' --kerberoasting '{kerb_file}'"
        stdout, stderr, code = run_command(cmd, "NetExec Kerberoasting", timeout=300)

        if os.path.exists(kerb_file):
            dest = kerb_file
            
            with open(dest, 'r') as f:
                hashes = f.read()
                if "$krb5tgs$" in hashes:
                    kerberoast_found = True
                    hash_count = hashes.count("$krb5tgs$")
                    console.print(f"[green]✓ Found {hash_count} Kerberoastable account(s)![/green]")
                    
                    # Show preview
                    lines = hashes.split('\n')[:3]
                    console.print(f"\n[dim]Preview:[/dim]")
                    for line in lines:
                        if line:
                            console.print(f"  {line[:80]}...")
                    
                    console.print(f"\n[yellow]💡 Next Steps:[/yellow]")
                    console.print(f"   hashcat -m 13100 {dest} /usr/share/wordlists/rockyou.txt")
                    console.print(f"   john --wordlist=/usr/share/wordlists/rockyou.txt {dest}")
    
    # Method 2: Impacket (fallback)
    if not kerberoast_found and tool_exists('impacket-GetUserSPNs'):
        console.print("[cyan]Trying Impacket GetUserSPNs...[/cyan]")
        
        cmd = f"impacket-GetUserSPNs {domain}/{username}:'{password}' -dc-ip {config.target_ip} -request"
        stdout, stderr, code = run_command(cmd, "Impacket Kerberoasting", timeout=300)
        
        if "$krb5tgs$" in stdout:
            save_output("impacket_kerberoast.txt", stdout, command=cmd)
            console.print("[green]✓ Kerberoast hashes found with Impacket[/green]")
            kerberoast_found = True
    
    if not kerberoast_found:
        console.print("[yellow]No Kerberoastable accounts found[/yellow]")

def test_credentials_everywhere():
    """Test credentials against all discovered services"""
    if not config.credentials:
        return
    
    console.print("\n[bold cyan]═══ Credential Validation ═══[/bold cyan]")
    
    # Parse credentials
    if '/' in config.credentials:
        domain_user, password = config.credentials.rsplit(':', 1)
        if '/' in domain_user:
            domain, username = domain_user.split('/', 1)
        else:
            domain = None
            username = domain_user
    else:
        username, password = config.credentials.rsplit(':', 1)
        domain = None
    
    console.print(f"[yellow]Testing: {domain+'/' if domain else ''}{username}[/yellow]\n")
    
    results = {}
    
    # Test SMB
    if ('445' in config.discovered_ports or '139' in config.discovered_ports) and tool_exists('netexec'):
        console.print("[cyan]→ Testing SMB...[/cyan]")
        cmd = f"netexec smb {config.target_ip} -u '{username}' -p '{password}'"
        if domain:
            cmd += f" -d '{domain}'"
        stdout, stderr, code = run_command(cmd, "SMB credential test", show_command=False)
        
        is_admin = "Pwn3d!" in stdout
        is_valid = is_admin or "[+]" in stdout or "STATUS_SUCCESS" in stdout
        results['SMB'] = ('Admin' if is_admin else 'Valid') if is_valid else 'Invalid'
    
    # Test WinRM
    if ('5985' in config.discovered_ports or '5986' in config.discovered_ports) and tool_exists('netexec'):
        console.print("[cyan]→ Testing WinRM...[/cyan]")
        cmd = f"netexec winrm {config.target_ip} -u '{username}' -p '{password}'"
        if domain:
            cmd += f" -d '{domain}'"
        stdout, stderr, code = run_command(cmd, "WinRM credential test", show_command=False)
        
        is_admin = "Pwn3d!" in stdout
        is_valid = is_admin or "[+]" in stdout
        results['WinRM'] = ('Admin' if is_admin else 'Valid') if is_valid else 'Invalid'
    
    # Test RDP
    if '3389' in config.discovered_ports and tool_exists('netexec'):
        console.print("[cyan]→ Testing RDP...[/cyan]")
        cmd = f"netexec rdp {config.target_ip} -u '{username}' -p '{password}'"
        if domain:
            cmd += f" -d '{domain}'"
        stdout, stderr, code = run_command(cmd, "RDP credential test", show_command=False)
        is_valid = "[+]" in stdout or "Authentication successful" in stdout
        results['RDP'] = 'Valid' if is_valid else 'Invalid'
    
    # Test MSSQL
    if '1433' in config.discovered_ports and tool_exists('netexec'):
        console.print("[cyan]→ Testing MSSQL...[/cyan]")
        cmd = f"netexec mssql {config.target_ip} -u '{username}' -p '{password}'"
        if domain:
            cmd += f" -d '{domain}'"
        stdout, stderr, code = run_command(cmd, "MSSQL credential test", show_command=False)
        
        is_admin = "Pwn3d!" in stdout
        is_valid = is_admin or "[+]" in stdout
        results['MSSQL'] = ('Admin' if is_admin else 'Valid') if is_valid else 'Invalid'
    
    # Test SSH (if domain machine has SSH)
    if '22' in config.discovered_ports:
        console.print("[cyan]→ Testing SSH...[/cyan]")
        cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {username}@{config.target_ip} 'echo SUCCESS' 2>/dev/null"
        stdout, stderr, code = run_command(cmd, "SSH credential test", show_command=False)
        results['SSH'] = 'Valid' if 'SUCCESS' in stdout else 'Invalid'
    
    # Display results table
    console.print(f"\n[bold cyan]Credential Test Results:[/bold cyan]")
    table = Table(box=box.ROUNDED)
    table.add_column("Service", style="cyan", width=12)
    table.add_column("Status", style="yellow", width=15)
    
    admin_access = []
    valid_access = []
    
    for service, status in results.items():
        if status == 'Admin':
            table.add_row(service, f"[red]✓ Admin Access[/red]")
            admin_access.append(service)
        elif status == 'Valid':
            table.add_row(service, f"[green]✓ Valid[/green]")
            valid_access.append(service)
        else:
            table.add_row(service, f"[dim]✗ Invalid[/dim]")
    
    console.print(table)
    
    # Provide recommendations
    if admin_access or valid_access:
        rec_lines = []

        if 'Admin' in results.get('SMB', ''):
            rec_lines.append(f"[bold red]CRITICAL - SMB Admin Access (Pwn3d!)[/bold red]")
            rec_lines.append(f"  [bold yellow]impacket-psexec {domain+'/' if domain else ''}{username}:'{password}'@{config.target_ip}[/bold yellow]")
            rec_lines.append(f"  [bold yellow]impacket-secretsdump {domain+'/' if domain else ''}{username}:'{password}'@{config.target_ip}[/bold yellow]")
            rec_lines.append("")

        if 'Admin' in results.get('WinRM', '') or 'Valid' in results.get('WinRM', ''):
            winrm_label = "[bold red]CRITICAL - WinRM Admin Access[/bold red]" if 'Admin' in results.get('WinRM', '') else "[bold green]WinRM Access[/bold green]"
            rec_lines.append(winrm_label)
            rec_lines.append(f"  [bold yellow]evil-winrm -i {config.target_ip} -u {username} -p '{password}'" + (f" -d {domain}" if domain else "") + "[/bold yellow]")
            rec_lines.append("")

        if 'Admin' in results.get('MSSQL', '') or 'Valid' in results.get('MSSQL', ''):
            mssql_label = "[bold red]CRITICAL - MSSQL Admin Access[/bold red]" if 'Admin' in results.get('MSSQL', '') else "[bold green]MSSQL Access[/bold green]"
            rec_lines.append(mssql_label)
            rec_lines.append(f"  [bold yellow]impacket-mssqlclient {domain+'/' if domain else ''}{username}:'{password}'@{config.target_ip}[/bold yellow]")
            rec_lines.append("")

        if 'Valid' in results.get('SSH', ''):
            rec_lines.append(f"[bold green]SSH Access[/bold green]")
            rec_lines.append(f"  [bold yellow]ssh {username}@{config.target_ip}[/bold yellow]")
            rec_lines.append("")

        if 'Valid' in results.get('RDP', ''):
            rec_lines.append(f"[bold green]RDP Access[/bold green]")
            rec_lines.append(f"  [bold yellow]xfreerdp /v:{config.target_ip} /u:{username} /p:'{password}'" + (f" /d:{domain}" if domain else "") + "[/bold yellow]")
            rec_lines.append("")

        border = "red" if admin_access else "green"
        title = "EXPLOITATION PATHS" if admin_access else "Recommended Actions"
        console.print(Panel('\n'.join(rec_lines), title=f"[bold]{title}[/bold]", border_style=border, padding=(1, 2)))
    
    # Save results
    save_output("credential_validation.txt", 
                f"Tested: {domain+'/' if domain else ''}{username}\n\n" + 
                "Results:\n" + 
                "\n".join([f"{k}: {v}" for k, v in results.items()]))

def enumerate_ad_shares_deep():
    """Deep enumeration of SMB shares looking for sensitive files"""
    console.print("\n[bold cyan]═══ Deep Share Enumeration ═══[/bold cyan]")

    username = config.ad_username
    password = config.ad_password
    domain = config.ad_domain

    if not username or not password:
        console.print("[dim]Skipping deep share enumeration (requires credentials)[/dim]")
        return

    if not tool_exists('netexec'):
        console.print("[yellow]NetExec not found, skipping[/yellow]")
        return
    
    console.print("[cyan]Searching shares for interesting files...[/cyan]")
    console.print("[dim]Looking for: passwords, configs, keys, scripts[/dim]\n")
    
    auth = f"-u '{username}' -p '{password}'"
    if domain:
        auth += f" -d '{domain}'"
    
    # Use spider_plus module to search
    patterns = ["password", "secret", "credential", "key", ".xml", ".config", ".ini"]
    
    found_files = []
    for pattern in patterns:
        console.print(f"[cyan]→ Searching for: {pattern}[/cyan]")
        cmd = f"netexec smb {config.target_ip} {auth} -M spider_plus -o READ_ONLY=false PATTERN='{pattern}'"
        stdout, stderr, code = run_command(cmd, f"Share search: {pattern}", timeout=180, show_command=False)
        
        if stdout and ("Found" in stdout or ".json" in stdout):
            save_output(f"share_search_{pattern}.txt", stdout, command=cmd)
            found_files.append(pattern)
    
    if found_files:
        console.print(f"\n[green]✓ Found interesting files matching: {', '.join(found_files)}[/green]")
        console.print(f"[yellow]💡 Review files in: {config.output_dir}/share_search_*.txt[/yellow]")
    else:
        console.print("[yellow]No sensitive files found in readable shares[/yellow]")

def enumerate_ad_gpp():
    """Check for Group Policy Preferences passwords"""
    console.print("\n[bold cyan]═══ GPP Password Extraction ═══[/bold cyan]")

    username = config.ad_username
    password = config.ad_password
    domain = config.ad_domain

    if not all([username, password, domain]):
        console.print("[dim]Skipping GPP extraction (requires username, password, and domain)[/dim]")
        return

    if not tool_exists('netexec'):
        console.print("[yellow]NetExec not found, skipping[/yellow]")
        return

    console.print("[cyan]Checking SYSVOL for GPP passwords...[/cyan]")
    
    cmd = f"netexec smb {config.target_ip} -u '{username}' -p '{password}' -d '{domain}' -M gpp_password"
    stdout, stderr, code = run_command(cmd, "GPP Password search", timeout=120)
    
    if "cpassword" in stdout.lower() or "password" in stdout.lower():
        console.print("[green]✓ GPP passwords found in SYSVOL![/green]")
        save_output("gpp_passwords.txt", stdout, command=cmd)
        
        # Extract and show any found passwords
        passwords = re.findall(r'Password.*?:\s*(.+)', stdout, re.IGNORECASE)
        if passwords:
            console.print(f"\n[yellow]💡 Found credentials:[/yellow]")
            for pwd in passwords[:5]:  # Show first 5
                console.print(f"   • {pwd}")
    else:
        console.print("[yellow]No GPP passwords found[/yellow]")

def enumerate_ad_asreproast_noauth():
    """Attempt AS-REP roasting without authentication"""
    console.print("\n[bold cyan]═══ AS-REP Roasting (No Auth) ═══[/bold cyan]")
    
    if '88' not in config.discovered_ports:
        console.print("[dim]Kerberos port 88 not open, skipping[/dim]")
        return
    
    domain = config.discovered_hosts[0].split('.')[-2:] if config.discovered_hosts else None
    if domain and isinstance(domain, list):
        domain = '.'.join(domain)
    
    if not domain:
        domain = prompt_user("[yellow]Domain name (e.g., htb.local):[/yellow] ").strip()
        if not domain:
            console.print("[dim]Domain required, skipping[/dim]")
            return
    
    if tool_exists('impacket-GetNPUsers'):
        console.print(f"[cyan]Checking for AS-REP roastable accounts on {domain}...[/cyan]")
        
        # Try with common usernames
        output_file = os.path.join(config.output_dir, "asreproast_nousers.txt")
        cmd = f"impacket-GetNPUsers {domain}/ -dc-ip {config.target_ip} -request -format hashcat -outputfile {output_file}"
        stdout, stderr, code = run_command(cmd, "AS-REP roast (no auth)", timeout=60, show_command=False)
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                content = f.read()
                if "$krb5asrep$" in content:
                    console.print("[green]✓ Found AS-REP roastable accounts![/green]")
                    console.print(f"\n[yellow]💡 Crack hashes:[/yellow]")
                    console.print(f"   hashcat -m 18200 {output_file} /usr/share/wordlists/rockyou.txt")
                else:
                    console.print("[yellow]No AS-REP roastable accounts found[/yellow]")
        else:
            console.print("[yellow]No AS-REP roastable accounts found[/yellow]")
    else:
        console.print("[dim]impacket-GetNPUsers not found, skipping[/dim]")

# ============================================================================
# PROTOCOL-SPECIFIC ENUMERATION
# ============================================================================

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

            # Use nmap scripts for FTP enumeration (more reliable than heredoc)
            cmd = f"nmap -p {port} --script ftp-anon,ftp-syst,ftp-vsftpd-backdoor {config.target_ip}"
            stdout, stderr, code = run_command(cmd, "FTP enumeration")

            if "Anonymous FTP login allowed" in stdout:
                console.print("[green]✓ Anonymous FTP login allowed[/green]")
            if "vsftpd" in stdout and "backdoor" in stdout.lower():
                console.print("[red]⚠ Potential vsftpd backdoor detected![/red]")

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
    web_ports = ['80', '443', '8080', '8443']
    if not any(p in config.discovered_ports for p in web_ports):
        return
    
    if not tool_exists('whatweb'):
        return
    
    console.print("\n[bold cyan]Detecting Web Technologies...[/bold cyan]")
    
    for port in ['80', '443', '8080', '8443']:
        if port in config.discovered_ports:
            protocol = 'https' if port in ['443', '8443'] else 'http'
            target = config.discovered_hosts[0] if config.discovered_hosts else config.target_ip
            url = f"{protocol}://{target}:{port}" if port not in ['80', '443'] else f"{protocol}://{target}"
            
            cmd = f"whatweb --no-colour -a 3 {url}"
            stdout, stderr, code = run_command(cmd, f"Technology detection: {url}", show_command=False)
            
            if stdout:
                console.print(f"\n[green]Technologies detected on {url}:[/green]")
                
                # Parse whatweb output
                # Format: http://example.com [200 OK] Country[US], HTTPServer[nginx/1.18.0], Title[Example]
                
                try:
                    # Extract the main findings part (after the URL and status)
                    if '[' in stdout:
                        # Split by URL and status code
                        parts = stdout.split(']', 1)
                        if len(parts) > 1:
                            # Get everything after first ]
                            tech_string = parts[1].strip()
                            if tech_string.startswith(','):
                                tech_string = tech_string[1:].strip()
                            
                            # Split by commas but respect brackets
                            technologies = []
                            current = ""
                            bracket_depth = 0
                            
                            for char in tech_string:
                                if char == '[':
                                    bracket_depth += 1
                                elif char == ']':
                                    bracket_depth -= 1
                                elif char == ',' and bracket_depth == 0:
                                    if current.strip():
                                        technologies.append(current.strip())
                                    current = ""
                                    continue
                                current += char
                            
                            if current.strip():
                                technologies.append(current.strip())
                            
                            # Display in a clean format
                            for tech in technologies:
                                if tech:
                                    # Extract technology name and details
                                    if '[' in tech:
                                        tech_name = tech.split('[')[0].strip()
                                        tech_details = tech.split('[')[1].split(']')[0] if ']' in tech else ""
                                        if tech_details:
                                            console.print(f"  [cyan]•[/cyan] {tech_name}: [yellow]{tech_details}[/yellow]")
                                        else:
                                            console.print(f"  [cyan]•[/cyan] {tech_name}")
                                    else:
                                        console.print(f"  [cyan]•[/cyan] {tech}")
                    else:
                        # Fallback: just show first line cleaned up
                        console.print(f"  {stdout.splitlines()[0]}")
                        
                except Exception as e:
                    # If parsing fails, show raw output (cleaned)
                    console.print(f"  [dim]{stdout[:200]}...[/dim]")
                
                save_output(f"whatweb_port{port}.txt", stdout, command=cmd)

def nikto_scan():
    """Run Nikto web vulnerability scanner"""
    web_ports = ['80', '443', '8080', '8443']
    if not any(p in config.discovered_ports for p in web_ports):
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
    web_ports = ['80', '443', '8080', '8443']
    if not any(p in config.discovered_ports for p in web_ports):
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
        
        response = prompt_user("\n[yellow]Run Nuclei vulnerability scan? This may take a while (y/n):[/yellow] ").strip().lower()
        
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
- **Commands Executed:** {len(config.commands_run)}

---

"""
    
    # Add all collected sections
    report += "\n".join(config.markdown_report)
    
    # Add commands executed section
    report += """

---

## All Commands Executed

This section lists every command that was run during the enumeration for reproducibility.

"""
    
    for idx, cmd_entry in enumerate(config.commands_run, 1):
        report += f"""
### Command {idx}: {cmd_entry['description']}

**Timestamp:** {cmd_entry['timestamp']}

```bash
{cmd_entry['command']}
```

"""
    
    # Add summary
    report += f"""

---

## Summary Statistics

- **Open Ports:** {len(config.discovered_ports)}
- **Discovered Hostnames:** {len(config.discovered_hosts)}
- **Services Enumerated:** {len([s for s in config.discovered_ports.values() if s.get('service')])}
- **Total Commands Run:** {len(config.commands_run)}

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
        description="HTB Enumeration Tool v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-t', '--target', help='Target IP, CIDR (10.10.110.0/24), or range (10.10.110.1-254)')
    parser.add_argument('-s', '--stealth', action='store_true', help='Use stealth mode (slower, quieter)')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--quick', action='store_true', help='Quick scan (skip deep enumeration)')
    parser.add_argument('--no-browser', action='store_true', help='Disable auto-opening browser dashboard')

    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Check prerequisites
    check_prerequisites()
    
    # Configuration
    if args.target:
        if not validate_target(args.target):
            console.print("[red]Invalid target format. Use: IP, CIDR (10.10.110.0/24), or range (10.10.110.1-254)[/red]")
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

    # Start browser dashboard
    start_dashboard(open_browser=not args.no_browser)

    # Set up signal handler for Ctrl+Z to skip phases
    signal.signal(signal.SIGTSTP, handle_skip_signal)
    
    # Info message about controls
    console.print("\n[bold cyan]═══ Controls ═══[/bold cyan]")
    console.print("[yellow]Ctrl+C[/yellow] = Exit entire script")
    console.print("[yellow]Ctrl+Z[/yellow] = Skip current phase (then type 'fg' + Enter to continue)")
    console.print("═" * 40 + "\n")

    try:
        # Check if target is a network range - do host discovery first
        if is_network_range(config.target_ip):
            config.is_range_scan = True
            live_hosts = run_phase(discover_live_hosts, "Phase 0: Host Discovery")

            if not live_hosts:
                console.print("[red]No live hosts found in range. Exiting.[/red]")
                sys.exit(0)

            # Let user choose which host to enumerate
            console.print("\n[bold cyan]═══ Host Selection ═══[/bold cyan]")
            console.print("Enter host number to enumerate, 'all' for all hosts, or 'q' to quit:")
            for idx, host in enumerate(live_hosts, 1):
                console.print(f"  [cyan]{idx}[/cyan]: {host}")

            selection = prompt_user("\n[bold yellow]Select host(s):[/bold yellow] ").strip().lower()

            if selection == 'q':
                console.print("[yellow]Exiting.[/yellow]")
                sys.exit(0)
            elif selection == 'all':
                hosts_to_scan = live_hosts
            else:
                try:
                    idx = int(selection) - 1
                    if 0 <= idx < len(live_hosts):
                        hosts_to_scan = [live_hosts[idx]]
                    else:
                        console.print("[red]Invalid selection. Exiting.[/red]")
                        sys.exit(1)
                except ValueError:
                    console.print("[red]Invalid selection. Exiting.[/red]")
                    sys.exit(1)

            # Enumerate each selected host
            for host_ip in hosts_to_scan:
                console.print(f"\n[bold magenta]{'═' * 60}[/bold magenta]")
                console.print(f"[bold magenta]  Enumerating Host: {host_ip}[/bold magenta]")
                console.print(f"[bold magenta]{'═' * 60}[/bold magenta]\n")

                # Update target to current host
                original_target = config.target_ip
                config.target_ip = host_ip

                # Create subdirectory for this host
                host_dir = os.path.join(config.output_dir, host_ip.replace('.', '_'))
                os.makedirs(host_dir, exist_ok=True)
                original_output_dir = config.output_dir
                config.output_dir = host_dir

                # Reset discovered data for this host
                config.discovered_ports = {}
                config.discovered_hosts = []

                # Run enumeration for this host
                open_ports = run_phase(nmap_basic_scan, f"Port Discovery: {host_ip}")

                if open_ports:
                    run_phase(nmap_detailed_scan, f"Service Detection: {host_ip}", open_ports)

                    if config.discovered_hosts:
                        run_phase(update_hosts_file, f"Hostname Integration: {host_ip}")

                    run_phase(analyze_ssl_certificates, f"SSL Analysis: {host_ip}")

                    if any(p in config.discovered_ports for p in ['80', '443', '8080', '8443']):
                        for port in ['80', '443', '8080', '8443']:
                            if port in config.discovered_ports:
                                run_phase(enumerate_web_directories, f"Web Enum: {host_ip}:{port}", port)

                    run_phase(enumerate_smb, f"SMB Enumeration: {host_ip}")
                    run_phase(enumerate_additional_services, f"Additional Services: {host_ip}")
                else:
                    console.print(f"[yellow]No open ports on {host_ip}, skipping...[/yellow]")

                # Restore output directory for next host
                config.output_dir = original_output_dir

            # Restore original target and generate final report
            config.target_ip = original_target
            generate_markdown_report()
            console.print(f"\n[green]✓ Enumeration complete! Results saved to: {config.output_dir}[/green]")
            sys.exit(0)

        # Single IP - proceed with normal flow
        # Phase 1: Initial port discovery
        open_ports = run_phase(nmap_basic_scan, "Phase 1: Initial Port Discovery")

        if not open_ports:
            console.print("[red]No open ports found. Exiting.[/red]")
            sys.exit(0)
        
        # Phase 2: Detailed service enumeration
        run_phase(nmap_detailed_scan, "Phase 2: Service Detection", open_ports)
        
        # Phase 3: Update hosts file if needed
        if config.discovered_hosts:
            run_phase(update_hosts_file, "Phase 3: Hostname Integration")
        
        # Phase 4: SSL certificate analysis
        run_phase(analyze_ssl_certificates, "Phase 4: SSL Analysis")
        
        # Phase 5: Web enumeration
        if any(p in config.discovered_ports for p in ['80', '443', '8080', '8443']):
            for port in ['80', '443', '8080', '8443']:
                if port in config.discovered_ports:
                    run_phase(enumerate_web_directories, f"Phase 5: Web Directory Enumeration (Port {port})", port)
            
            run_phase(enumerate_vhosts, "Phase 5: VHOST Discovery")
            run_phase(web_technology_detection, "Phase 5: Web Technology Detection")
        
        # Phase 6: DNS enumeration
        run_phase(enumerate_dns, "Phase 6: DNS Enumeration")
        
        # Phase 7: Active Directory enumeration
        run_phase(enumerate_active_directory, "Phase 7: Active Directory Enumeration")
        
        # Phase 8: SMB enumeration
        run_phase(enumerate_smb, "Phase 8: SMB Enumeration")
        
        # Phase 9: Additional services
        if not args.quick:
            run_phase(enumerate_additional_services, "Phase 9: Additional Services")
        
        # Phase 10: Advanced Web Enumeration
        if any(p in config.discovered_ports for p in ['80', '443', '8080', '8443']):
            if not args.quick:
                console.print(Panel.fit(
                    "[bold cyan]Phase 10: Advanced Web Enumeration[/bold cyan]",
                    border_style="cyan"
                ))
                run_phase(nikto_scan, "Phase 10: Nikto Scan")
                run_phase(cms_detection, "Phase 10: CMS Detection")
                run_phase(ssl_vulnerability_scan, "Phase 10: SSL Vulnerability Scan")
                run_phase(vulnerability_scanning, "Phase 10: Nuclei Vulnerability Scan")
        
        # Phase 11: Protocol-Specific Deep Enumeration
        if not args.quick:
            console.print(Panel.fit(
                "[bold cyan]Phase 11: Protocol-Specific Deep Enumeration[/bold cyan]",
                border_style="cyan"
            ))
            run_phase(nfs_enumeration, "Phase 11: NFS Enumeration")
            run_phase(snmp_enumeration, "Phase 11: SNMP Enumeration")
            run_phase(netbios_enumeration, "Phase 11: NetBIOS Enumeration")
            run_phase(rpc_enumeration, "Phase 11: RPC Enumeration")
            run_phase(impacket_enumeration, "Phase 11: Impacket Enumeration")
        
        # Generate final reports
        report_path = generate_markdown_report()
        html_report_path = generate_html_report()
        emit_event('scan_complete', {
            'ports': len(config.discovered_ports),
            'hosts': len(config.discovered_hosts),
            'commands': len(config.commands_run),
        })

        # Final summary
        dashboard_line = "\n[cyan]Dashboard:[/cyan] http://127.0.0.1:5000/report" if config.dashboard_enabled else ""
        console.print(Panel.fit(
            f"""[bold green]Enumeration Complete![/bold green]

[cyan]Results saved to:[/cyan] {config.output_dir}
[cyan]Markdown report:[/cyan] {report_path}
[cyan]HTML report:[/cyan] {html_report_path}{dashboard_line}

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
