#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cloud Killer - Advanced Subdomain Discovery Tool
Bypasses Cloud Protection and finds hidden subdomains
By: FD (github.com/next-code-community)
Enhanced version with Discord webhook integration
"""

import os
import sys
import json
import time
import signal
import socket
import argparse
from datetime import datetime
from urllib.parse import urlparse
import threading
import concurrent.futures
import logging
import platform
import configparser
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('CloudKiller')

# Global variables
FOUND_DOMAINS = []
PROGRESS_LOCK = threading.Lock()
TOTAL_CHECKED = 0
TOTAL_SUBDOMAINS = 0
START_TIME = time.time()
CONFIG_FILE = 'cloudkiller.conf'

# Check if the requests library is available, install it if not
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print('[!] requests library not found. Please install it by: pip3 install requests')
    try:
        choice = input('[?] Do you want to install this library now? (Y/n) >> ')
        if choice.lower() in ['y', 'yes', '']:
            print('[+] Installing requests...')
            if platform.system() == 'Windows':
                os.system('pip install requests')
            else:
                os.system('pip3 install requests')
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            print('[+] Successfully installed requests!')
        else:
            print('[-] Exiting...')
            sys.exit(1)
    except KeyboardInterrupt:
        print('\n[-] Installation cancelled. Exiting...')
        sys.exit(1)

# Check if the other required libraries are available
try:
    import subprocess
    import re
    if platform.system() != 'Windows':  # multiprocessing has issues on some Windows setups
        import multiprocessing
except ImportError as e:
    print(f'[!] Required library not found: {e.name}')
    print('[!] This should be included in standard Python. Please check your installation.')
    sys.exit(1)

# Check if colorama is installed for better cross-platform color support
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)  # Initialize colorama
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    try:
        choice = input('[?] Colorama library not found. Do you want to install it for better color support? (Y/n) >> ')
        if choice.lower() in ['y', 'yes', '']:
            print('[+] Installing colorama...')
            if platform.system() == 'Windows':
                os.system('pip install colorama')
            else:
                os.system('pip3 install colorama')
            from colorama import init, Fore, Back, Style
            init(autoreset=True)
            HAS_COLORAMA = True
            print('[+] Successfully installed colorama!')
    except KeyboardInterrupt:
        print('\n[i] Continuing without colorama...')

# Color functions
def green(text):
    if HAS_COLORAMA:
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}"
    return f'\033[1;32;40m{text}\033[0m'

def red(text):
    if HAS_COLORAMA:
        return f"{Fore.RED}{text}{Style.RESET_ALL}"
    return f'\033[0;31;40m{text}\033[0m'

def yellow(text):
    if HAS_COLORAMA:
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
    return f'\033[1;33;40m{text}\033[0m'

def blue(text):
    if HAS_COLORAMA:
        return f"{Fore.BLUE}{text}{Style.RESET_ALL}"
    return f'\033[1;34;40m{text}\033[0m'

def cyan(text):
    if HAS_COLORAMA:
        return f"{Fore.CYAN}{text}{Style.RESET_ALL}"
    return f'\033[1;36;40m{text}\033[0m'

def magenta(text):
    if HAS_COLORAMA:
        return f"{Fore.MAGENTA}{text}{Style.RESET_ALL}"
    return f'\033[1;35;40m{text}\033[0m'

# Banner and information
def print_banner():
    """Display the tool's banner."""
    banner = f"""
{green('''   _____ _                 _    _  ___ _ _           
  / ____| |               | |  | |/ (_) | |          
 | |    | | ___  _   _  __| |  | ' / _| | | ___ _ __ 
 | |    | |/ _ \\| | | |/ _` |  |  < | | | |/ _ \\ '__|
 | |____| | (_) | |_| | (_| |  | . \\| | | |  __/ |   
  \\_____|_|\\___/ \\__,_|\\__,_|  |_|\\_\\_|_|_|\\___|_|   ''')}
 {yellow('====================================================')}
                    {blue('Cloud Killer v2.0')}
                {magenta('github.com/next-code-community')}
            {cyan('Advanced Cloud Protection Bypass Tool')}
 {yellow('====================================================')}
"""
    print(banner)

# Configuration management
def create_default_config():
    """Create a default configuration file if it doesn't exist."""
    config = configparser.ConfigParser()
    
    config['General'] = {
        'threads': '50',
        'timeout': '5',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'verify_ssl': 'False',
        'save_screenshots': 'False',
        'screenshot_dir': 'screenshots'
    }
    
    config['HTTP'] = {
        'methods': 'GET',
        'follow_redirects': 'True',
        'max_redirects': '3',
        'headers': 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
    }
    
    config['Output'] = {
        'verbose': 'True',
        'show_progress': 'True',
        'log_file': 'cloudkiller.log',
        'output_format': 'csv'
    }
    
    config['Discord'] = {
        'enabled': 'False',
        'webhook_url': '',
        'notification_threshold': '1',
        'embed_color': '5814783'
    }
    
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)
    
    print(green(f'[+] Created default configuration file: {CONFIG_FILE}'))
    return config

def load_config():
    """Load configuration from file or create a default one."""
    if not os.path.exists(CONFIG_FILE):
        return create_default_config()
    
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return config

# Discord webhook integration
def send_discord_notification(webhook_url, domain, ip_address, status_code, response_time, config):
    """Send a notification to Discord webhook when a subdomain is found."""
    if not webhook_url:
        return
    
    try:
        embed_color = int(config['Discord']['embed_color'])
    except (KeyError, ValueError):
        embed_color = 5814783  # Default color (green)
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create a properly formatted Discord embed
    data = {
        "embeds": [{
            "title": "☁️ CloudKiller - Domain Found!",
            "description": f"A new subdomain has been discovered for target: `{domain.split('.', 1)[1]}`",
            "color": embed_color,
            "fields": [
                {
                    "name": "📋 Subdomain",
                    "value": f"`{domain}`",
                    "inline": True
                },
                {
                    "name": "🌐 IP Address",
                    "value": f"`{ip_address}`",
                    "inline": True
                },
                {
                    "name": "🔢 Status Code",
                    "value": f"`{status_code}`",
                    "inline": True
                },
                {
                    "name": "⏱️ Response Time",
                    "value": f"`{response_time:.2f}ms`",
                    "inline": True
                },
                {
                    "name": "🔗 URL",
                    "value": f"http://{domain}",
                    "inline": False
                },
                {
                    "name": "⏰ Discovery Time",
                    "value": current_time,
                    "inline": False
                }
            ],
            "footer": {
                "text": "CloudKiller v2.0 by FD"
            },
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }]
    }
    
    try:
        response = requests.post(webhook_url, json=data)
        if response.status_code != 204:
            logger.warning(f"Discord webhook returned status code {response.status_code}")
    except Exception as e:
        logger.error(f"Error sending Discord notification: {e}")

# Domain and network utilities
def is_valid_domain(domain):
    """Check if a domain is valid."""
    if not domain:
        return False
    
    # Simple regex for domain validation
    domain_regex = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_regex, domain))

def clean_domain(domain):
    """Clean and normalize a domain name."""
    # Remove http/https protocol if present
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        domain = parsed.netloc
    
    # Remove www. prefix if present
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Remove trailing slash if present
    if domain.endswith('/'):
        domain = domain[:-1]
    
    return domain.lower()

def get_ip_address(domain):
    """Get IP address for a domain using socket instead of ping for cross-platform compatibility."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def ping_domain(domain):
    """Ping a domain to check if it's reachable and get its IP address."""
    try:
        if platform.system() == "Windows":
            ping_command = f"ping -n 1 -w 1000 {domain}"
        else:
            ping_command = f"ping -c 1 -W 1 {domain}"
        
        output = subprocess.check_output(ping_command, shell=True).decode('utf-8')
        ip_matches = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', output)
        
        return ip_matches[0] if ip_matches else None
    except Exception:
        return None

def check_domain_dns(domain):
    """Check if a domain resolves in DNS."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

# Domain checking functionality
def check_domain(domain, config, report_file, discord_webhook=None):
    """Check if a domain exists and is accessible."""
    global TOTAL_CHECKED
    
    # Update progress
    with PROGRESS_LOCK:
        TOTAL_CHECKED += 1
    
    # Configuration parameters
    timeout = int(config['General']['timeout'])
    verify_ssl = config['General'].getboolean('verify_ssl')
    user_agent = config['General']['user_agent']
    
    headers = {
        'User-Agent': user_agent
    }
    
    # Add additional headers from config
    if 'headers' in config['HTTP']:
        for header_line in config['HTTP']['headers'].split('\n'):
            if ':' in header_line:
                key, value = header_line.split(':', 1)
                headers[key.strip()] = value.strip()
    
    protocols = ['http', 'https']
    
    for protocol in protocols:
        try:
            start_time = time.perf_counter()
            url = f"{protocol}://{domain}"
            
            response = requests.get(
                url, 
                headers=headers, 
                timeout=timeout, 
                verify=verify_ssl,
                allow_redirects=config['HTTP'].getboolean('follow_redirects')
            )
            
            end_time = time.perf_counter()
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            # If we got any valid response, consider it found
            if response.status_code:
                # Get IP using socket for reliability
                ip_address = get_ip_address(domain)
                
                # If socket method fails, try ping as fallback
                if not ip_address:
                    ip_address = ping_domain(domain)
                
                if ip_address:
                    # Format the output
                    status_str = f"{response.status_code}"
                    if response.status_code == 200:
                        status_str = green(status_str)
                    elif response.status_code in [403, 401]:
                        status_str = yellow(status_str)
                    elif response.status_code >= 500:
                        status_str = red(status_str)
                    
                    discovery_message = (f"\n[+] Found: {green(domain)} | "
                                         f"IP: {cyan(ip_address)} | "
                                         f"Status: {status_str} | "
                                         f"Response: {magenta(f'{response_time:.1f}ms')}")
                    
                    print(discovery_message)
                    
                    # Write to report file
                    with open(report_file, 'a') as f:
                        f.write(f"{domain},{ip_address},{response.status_code},{protocol},{response_time:.1f}\n")
                    
                    # Add to global list of found domains
                    FOUND_DOMAINS.append({
                        'domain': domain,
                        'ip': ip_address,
                        'status': response.status_code,
                        'protocol': protocol,
                        'response_time': response_time
                    })
                    
                    # Send Discord notification if enabled
                    if discord_webhook and config['Discord'].getboolean('enabled'):
                        threshold = int(config['Discord']['notification_threshold'])
                        if len(FOUND_DOMAINS) % threshold == 0:  # Only send every Nth finding
                            send_discord_notification(discord_webhook, domain, ip_address, 
                                                     response.status_code, response_time, config)
                    
                    # No need to check HTTPS if HTTP already worked
                    return True
                
        except requests.ConnectionError:
            # Connection error usually means domain doesn't exist or isn't accessible
            pass
        except requests.Timeout:
            # Timeout usually means domain exists but is slow
            # Could be worth noting in some cases
            if check_domain_dns(domain):
                print(f"\n[!] Timeout for {yellow(domain)} but DNS resolves")
        except Exception as e:
            # For debugging, uncomment this:
            # print(f"Error checking {domain}: {str(e)}")
            pass
    
    # Show progress if requested
    if config['Output'].getboolean('show_progress'):
        progress = (TOTAL_CHECKED / TOTAL_SUBDOMAINS) * 100
        elapsed = time.time() - START_TIME
        rate = TOTAL_CHECKED / elapsed if elapsed > 0 else 0
        
        # Print progress indicator that overwrites itself
        print(f"\r[-] Progress: {progress:.1f}% | Checked: {TOTAL_CHECKED}/{TOTAL_SUBDOMAINS} | "
              f"Found: {len(FOUND_DOMAINS)} | Rate: {rate:.1f}/s", end="", flush=True)
    
    return False

# Subdomain processing
def load_subdomains(wordlist_path):
    """Load subdomains from a wordlist file."""
    if not os.path.exists(wordlist_path):
        print(red(f"[!] Error: Wordlist file not found: {wordlist_path}"))
        sys.exit(1)
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        print(green(f"[+] Loaded {len(subdomains)} subdomains from {wordlist_path}"))
        return subdomains
    except Exception as e:
        print(red(f"[!] Error loading wordlist: {str(e)}"))
        sys.exit(1)

def process_subdomains(target_domain, wordlist_path, report_file, config, discord_webhook=None):
    """Process subdomains from a wordlist."""
    global TOTAL_SUBDOMAINS, START_TIME
    
    # Clean the target domain
    target_domain = clean_domain(target_domain)
    
    if not is_valid_domain(target_domain):
        print(red(f"[!] Invalid domain: {target_domain}"))
        return

    # Load subdomains
    subdomains = load_subdomains(wordlist_path)
    TOTAL_SUBDOMAINS = len(subdomains)
    START_TIME = time.time()
    
    # Prepare full domain names
    full_domains = [f"{sub}.{target_domain}" for sub in subdomains]
    
    # Optional: shuffle domains for less predictable scanning pattern
    random.shuffle(full_domains)
    
    print(yellow(f"[*] Starting scan of {TOTAL_SUBDOMAINS} subdomains for {target_domain}..."))
    print(yellow(f"[*] Results will be saved to {report_file}"))
    
    # Write CSV header to report file
    with open(report_file, 'w') as f:
        f.write("subdomain,ip_address,status_code,protocol,response_time_ms\n")
    
    # Determine thread count
    try:
        thread_count = int(config['General']['threads'])
    except (KeyError, ValueError):
        # Default to CPU count or 50, whichever is less
        thread_count = min(50, os.cpu_count() * 2 if os.cpu_count() else 50)
    
    print(cyan(f"[*] Using {thread_count} threads"))
    
    try:
        # Use ThreadPoolExecutor for Windows compatibility
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = []
            for domain in full_domains:
                future = executor.submit(check_domain, domain, config, report_file, discord_webhook)
                futures.append(future)
            
            # Wait for all futures to complete
            concurrent.futures.wait(futures)
    
    except KeyboardInterrupt:
        print(yellow("\n[!] Scan interrupted by user. Saving results..."))
    except Exception as e:
        print(red(f"\n[!] An error occurred: {str(e)}"))
    
    # Calculate and print statistics
    elapsed_time = time.time() - START_TIME
    print("\n" + "=" * 60)
    print(green(f"[+] Scan completed!"))
    print(f"[+] Total subdomains checked: {TOTAL_CHECKED}/{TOTAL_SUBDOMAINS}")
    print(f"[+] Found {len(FOUND_DOMAINS)} active subdomains")
    print(f"[+] Elapsed time: {elapsed_time:.2f} seconds")
    print(f"[+] Average speed: {TOTAL_CHECKED / elapsed_time:.2f} domains/second")
    print(f"[+] Results saved to: {report_file}")
    print("=" * 60)
    
    # Send a final summary to Discord if enabled
    if discord_webhook and config['Discord'].getboolean('enabled') and FOUND_DOMAINS:
        try:
            summary_data = {
                "embeds": [{
                    "title": "☁️ CloudKiller - Scan Completed",
                    "description": f"Scan of {target_domain} has completed",
                    "color": int(config['Discord']['embed_color']),
                    "fields": [
                        {
                            "name": "🎯 Target Domain",
                            "value": target_domain,
                            "inline": True
                        },
                        {
                            "name": "🔍 Subdomains Checked",
                            "value": str(TOTAL_CHECKED),
                            "inline": True
                        },
                        {
                            "name": "✅ Domains Found",
                            "value": str(len(FOUND_DOMAINS)),
                            "inline": True
                        },
                        {
                            "name": "⏱️ Elapsed Time",
                            "value": f"{elapsed_time:.2f} seconds",
                            "inline": True
                        }
                    ],
                    "footer": {
                        "text": "CloudKiller v2.0 by FD"
                    },
                    "timestamp": datetime.utcnow().isoformat()
                }]
            }
            
            requests.post(discord_webhook, json=summary_data)
        except Exception as e:
            logger.error(f"Error sending Discord summary: {e}")

def check_existing_report(domain):
    """Check if a report already exists for this domain and offer to resume."""
    report_name = f'Report_{domain}.csv'
    
    if os.path.exists(report_name):
        print(yellow(f"[!] A previous report for {domain} exists: {report_name}"))
        try:
            choice = input(yellow("[?] Do you want to (O)verwrite, (A)ppend to it, or (C)ancel? [O/A/C] >> "))
            
            if choice.lower() == 'o':
                return report_name  # Will be overwritten
            elif choice.lower() == 'a':
                # Read found domains from the existing report to prevent rechecking
                try:
                    with open(report_name, 'r') as f:
                        next(f)  # Skip header
                        for line in f:
                            parts = line.strip().split(',')
                            if len(parts) >= 2:
                                FOUND_DOMAINS.append({
                                    'domain': parts[0],
                                    'ip': parts[1],
                                    'status': parts[2] if len(parts) > 2 else 'unknown',
                                    'protocol': parts[3] if len(parts) > 3 else 'http',
                                    'response_time': float(parts[4]) if len(parts) > 4 else 0.0
                                })
                    print(green(f"[+] Loaded {len(FOUND_DOMAINS)} existing results from {report_name}"))
                except Exception as e:
                    print(red(f"[!] Error loading existing report: {str(e)}"))
                
                return report_name  # Will be appended to
            else:
                print(yellow("[!] Operation cancelled."))
                sys.exit(0)
        except KeyboardInterrupt:
            print("\n[-] Cancelled.")
            sys.exit(0)
    
    return report_name

def signal_handler(sig, frame):
    """Handle keyboard interruption (Ctrl+C)."""
    print(yellow("\n[!] Interrupted by user. Saving progress..."))
    sys.exit(0)

# Main function
def main():
    """Main function."""
    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Display banner
    print_banner()
    
    # Load configuration
    config = load_config()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='CloudKiller - Advanced Subdomain Discovery Tool')
    parser.add_argument('-d', '--domain', help='Target domain')
    parser.add_argument('-w', '--wordlist', help='Path to subdomain wordlist')
    parser.add_argument('-o', '--output', help='Output file name')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads')
    parser.add_argument('--webhook', help='Discord webhook URL')
    parser.add_argument('--config', help='Path to config file')
    
    args = parser.parse_args()
    
    # Override config with command line arguments
    if args.config:
        if os.path.exists(args.config):
            config.read(args.config)
            print(green(f"[+] Loaded configuration from {args.config}"))
        else:
            print(red(f"[!] Config file not found: {args.config}"))
    
    if args.threads:
        config['General']['threads'] = str(args.threads)
    
    # Get target domain
    target_domain = args.domain
    if not target_domain:
        try:
            target_domain = input(cyan('[?] Enter target domain (e.g., example.com): '))
        except KeyboardInterrupt:
            print("\n[-] Cancelled.")
            sys.exit(0)
    
    target_domain = clean_domain(target_domain)
    
    # Validate domain
    if not is_valid_domain(target_domain):
        print(red(f"[!] Invalid domain: {target_domain}"))
        sys.exit(1)
    
    # Get wordlist
    wordlist_path = args.wordlist
    if not wordlist_path:
        wordlist_path = 'subl.txt'  # Default
        
        if not os.path.exists(wordlist_path):
            try:
                wordlist_path = input(cyan(f'[?] Subdomain wordlist not found. Enter path to wordlist file: '))
            except KeyboardInterrupt:
                print("\n[-] Cancelled.")
                sys.exit(0)
    
    # Check if wordlist exists
    if not os.path.exists(wordlist_path):
        print(red(f"[!] Wordlist file not found: {wordlist_path}"))
        sys.exit(1)
    
    # Get output file name
    if args.output:
        report_file = args.output
    else:
        report_file = check_existing_report(target_domain)
    
    # Get Discord webhook
    discord_webhook = args.webhook
    if not discord_webhook and config['Discord'].getboolean('enabled'):
        discord_webhook = config['Discord']['webhook_url']
        
    if not discord_webhook:
        try:
            webhook_prompt = input(cyan('[?] Enter Discord webhook URL (leave empty to disable): '))
            if webhook_prompt.strip():
                discord_webhook = webhook_prompt
                config['Discord']['enabled'] = 'True'
                config['Discord']['webhook_url'] = discord_webhook
                
                # Save the webhook to config for future use
                with open(CONFIG_FILE, 'w') as configfile:
                    config.write(configfile)
        except KeyboardInterrupt:
            print("\n[-] Cancelled.")
            sys.exit(0)
    
    # Process subdomains
    process_subdomains(target_domain, wordlist_path, report_file, config, discord_webhook)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Cloud Killer was closed by user.")
    except Exception as e:
        print(red(f"\n[!] An unexpected error occurred: {str(e)}"))
        logger.exception("Unexpected error")
