
        #!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CloudKiller Pro - Advanced Subdomain Discovery & Cloud Protection Bypass Tool
By: FD (github.com/next-code-community)
Enhanced version with multiple passive DNS sources, WAF bypass, and advanced analysis
"""

import os
import sys
import json
import time
import signal
import socket
import argparse
import ipaddress
import threading
import ssl
import random
import hashlib
import base64
import concurrent.futures
import logging
import platform
import configparser
import re
import csv
import urllib.parse
from datetime import datetime
from pathlib import Path

# Define version
VERSION = "3.0.0"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('CloudKiller')

# Global variables
FOUND_DOMAINS = []
ACTIVE_THREADS = 0
PROGRESS_LOCK = threading.Lock()
PROXY_LOCK = threading.Lock()
TOTAL_CHECKED = 0
TOTAL_SUBDOMAINS = 0
START_TIME = time.time()
CONFIG_FILE = 'cloudkiller2.0.conf'
CURRENT_PROXY_INDEX = 0
PROXIES = []
DNS_SERVERS = []
RATE_LIMIT_DELAY = 0
BLOCKED_IPS = set()
RESUMED_SCAN = False
SCAN_ID = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
TEMP_DIR = Path('.cloudkiller_temp')
FINGERPRINTS = {}

# Required packages
REQUIRED_PACKAGES = {
    'requests': 'requests',
    'colorama': 'colorama',
    'dnspython': 'dns',
    'beautifulsoup4': 'bs4',
    'fake-useragent': 'fake_useragent',
    'tldextract': 'tldextract',
    'cryptography': 'cryptography',
    'lxml': 'lxml',
    'aiohttp': 'aiohttp',
    'whois': 'whois'
}

# Optional packages for additional features
OPTIONAL_PACKAGES = {
    'selenium': 'selenium',
    'playwright': 'playwright',
    'netaddr': 'netaddr',
    'mmh3': 'mmh3',  # For favicon hashing
    'python-nmap': 'nmap',
    'pyOpenSSL': 'OpenSSL',
    'shodan': 'shodan',
    'censys': 'censys'
}

# Check for temp directory
if not TEMP_DIR.exists():
    TEMP_DIR.mkdir(exist_ok=True)

# Import required packages and handle missing dependencies
def check_and_import_packages():
    missing_required = []
    installed_optional = []
    
    # Check required packages
    for package_name, module_name in REQUIRED_PACKAGES.items():
        try:
            __import__(module_name)
        except ImportError:
            missing_required.append(package_name)
    
    # Install missing required packages
    if missing_required:
        print(f"[!] Missing required packages: {', '.join(missing_required)}")
        try:
            choice = input("[?] Do you want to install them now? (Y/n) >> ")
            if choice.lower() in ['y', 'yes', '']:
                print("[+] Installing required packages...")
                for package in missing_required:
                    print(f"[*] Installing {package}...")
                    if platform.system() == 'Windows':
                        os.system(f'pip install {package}')
                    else:
                        os.system(f'pip3 install {package}')
                print("[+] Required packages installed. Restarting...")
                os.execl(sys.executable, sys.executable, *sys.argv)
            else:
                print("[-] Cannot continue without required packages. Exiting...")
                sys.exit(1)
        except KeyboardInterrupt:
            print("\n[-] Installation cancelled. Exiting...")
            sys.exit(1)
    
    # Check optional packages
    for package_name, module_name in OPTIONAL_PACKAGES.items():
        try:
            __import__(module_name)
            installed_optional.append(package_name)
        except ImportError:
            pass
    
    return installed_optional

# Import after verifying packages
installed_optional = check_and_import_packages()

# Now import the required packages
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from colorama import init, Fore, Back, Style
init(autoreset=True)
import dns.resolver
import bs4
from fake_useragent import UserAgent
import tldextract
import whois
from cryptography.fernet import Fernet

# Import optional packages if available
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    import censys.search
    CENSYS_AVAILABLE = True
except ImportError:
    CENSYS_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# Color functions
def green(text):
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}"

def red(text):
    return f"{Fore.RED}{text}{Style.RESET_ALL}"

def yellow(text):
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"

def blue(text):
    return f"{Fore.BLUE}{text}{Style.RESET_ALL}"

def cyan(text):
    return f"{Fore.CYAN}{text}{Style.RESET_ALL}"

def magenta(text):
    return f"{Fore.MAGENTA}{text}{Style.RESET_ALL}"

def white_on_red(text):
    return f"{Fore.WHITE}{Back.RED}{text}{Style.RESET_ALL}"

def black_on_green(text):
    return f"{Fore.BLACK}{Back.GREEN}{text}{Style.RESET_ALL}"

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
                {blue(f'CloudKiller Pro v{VERSION}')}
                {magenta('github.com/next-code-community')}
          {cyan('Advanced Cloud Protection Bypass Tool')}
 {yellow('====================================================')}
"""
    print(banner)
    
    # Print installed optional features
    if installed_optional:
        print(f"{cyan('[+] Optional features loaded:')} {', '.join(installed_optional)}")
    print(f"{yellow('[+] Session ID:')} {SCAN_ID}")
    print()

# Configuration management
def create_default_config():
    """Create a default configuration file if it doesn't exist."""
    config = configparser.ConfigParser()
    
    config['General'] = {
        'threads': '75',
        'timeout': '8',
        'user_agent_rotation': 'True',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'verify_ssl': 'False',
        'max_retries': '3',
        'screenshot_dir': 'screenshots',
        'temp_dir': '.cloudkiller_temp',
        'encrypt_logs': 'False',
        'proxy_enabled': 'False',
        'proxy_file': 'proxies.txt',
        'dns_servers': '8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222',
        'rate_limit_detection': 'True',
        'waf_bypass': 'True'
    }
    
    config['HTTP'] = {
        'methods': 'GET',
        'follow_redirects': 'True',
        'max_redirects': '5',
        'vhost_discovery': 'True',
        'fingerprint_waf': 'True',
        'headers': 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\nAccept-Language: en-US,en;q=0.5\nConnection: close'
    }
    
    config['Output'] = {
        'verbose': 'True',
        'show_progress': 'True',
        'log_file': 'cloudkiller.log',
        'output_format': 'csv',
        'json_output': 'True',
        'save_html': 'False',
        'save_headers': 'True'
    }
    
    config['Analysis'] = {
        'port_scan': 'False',
        'vuln_check': 'False',
        'directory_check': 'False',
        'ssl_info': 'True',
        'favicon_hash': 'True',
        'technology_detect': 'True',
        'screenshot': 'False',
        'whois_lookup': 'True'
    }
    
    config['Passive'] = {
        'use_passive_sources': 'True',
        'cert_transparency': 'True',
        'dns_bufferover': 'True',
        'threatcrowd': 'True',
        'virustotal': 'False',
        'shodan': 'False',
        'censys': 'False',
        'alienvault': 'True',
        'spyse': 'False',
        'securitytrails': 'False',
        'passive_timeout': '30'
    }
    
    config['API_Keys'] = {
        'virustotal': '',
        'securitytrails': '',
        'shodan': '',
        'censys_id': '',
        'censys_secret': '',
        'spyse': ''
    }
    
    config['Discord'] = {
        'enabled': 'False',
        'webhook_url': '',
        'notification_threshold': '1',
        'embed_color': '5814783',
        'send_summary': 'True',
        'send_screenshots': 'False'
    }
    
    config['Telegram'] = {
        'enabled': 'False',
        'bot_token': '',
        'chat_id': ''
    }
    
    config['Advanced'] = {
        'recursive_depth': '1',
        'subdomain_generation': 'True',
        'permutation_patterns': 'dev,stage,test,staging,prod,production,api,app,admin,portal',
        'random_subdomains': 'True',
        'random_count': '100',
        'wordlist_mutation': 'True',
        'dns_wildcard_check': 'True',
        'takeover_check': 'True',
        'ip_ranges': ''
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

# Generate encryption key
def get_or_create_encryption_key():
    key_file = TEMP_DIR / 'encryption.key'
    if key_file.exists():
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

# Discord webhook integration
def send_discord_notification(webhook_url, discovery_data, config, is_summary=False):
    """Send a notification to Discord webhook when a subdomain is found."""
    if not webhook_url:
        return
    
    try:
        embed_color = int(config['Discord']['embed_color'])
    except (KeyError, ValueError):
        embed_color = 5814783  # Default color (green)
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if is_summary:
        # Create a summary embed
        data = {
            "embeds": [{
                "title": "☁️ CloudKiller Pro - Scan Completed",
                "description": f"Scan of {discovery_data['target_domain']} has completed",
                "color": embed_color,
                "fields": [
                    {
                        "name": "🎯 Target Domain",
                        "value": discovery_data['target_domain'],
                        "inline": True
                    },
                    {
                        "name": "🔍 Subdomains Checked",
                        "value": str(discovery_data['total_checked']),
                        "inline": True
                    },
                    {
                        "name": "✅ Domains Found",
                        "value": str(discovery_data['total_found']),
                        "inline": True
                    },
                    {
                        "name": "⏱️ Elapsed Time",
                        "value": f"{discovery_data['elapsed_time']:.2f} seconds",
                        "inline": True
                    },
                    {
                        "name": "📊 Success Rate",
                        "value": f"{discovery_data['success_rate']:.2f}%",
                        "inline": True
                    },
                    {
                        "name": "🛡️ WAFs Detected",
                        "value": ', '.join(discovery_data['wafs']) if discovery_data['wafs'] else "None",
                        "inline": False
                    }
                ],
                "footer": {
                    "text": f"CloudKiller Pro v{VERSION} | Session: {SCAN_ID}"
                },
                "timestamp": datetime.utcnow().isoformat()
            }]
        }
    else:
        # Create a discovery embed
        domain = discovery_data['domain']
        ip_address = discovery_data['ip']
        status_code = discovery_data['status']
        response_time = discovery_data['response_time']
        protocol = discovery_data.get('protocol', 'http')
        server = discovery_data.get('server', 'Unknown')
        tech = discovery_data.get('technologies', [])
        
        data = {
            "embeds": [{
                "title": "☁️ CloudKiller Pro - Domain Found!",
                "description": f"A new subdomain has been discovered for target: `{domain.split('.', 1)[1] if '.' in domain else domain}`",
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
                        "name": "🖥️ Server",
                        "value": f"`{server}`",
                        "inline": True
                    },
                    {
                        "name": "🔗 URL",
                        "value": f"{protocol}://{domain}",
                        "inline": False
                    }
                ],
                "footer": {
                    "text": f"CloudKiller Pro v{VERSION} | Session: {SCAN_ID}"
                },
                "timestamp": datetime.utcnow().isoformat()
            }]
        }
        
        # Add technologies if found
        if tech:
            data["embeds"][0]["fields"].append({
                "name": "🧰 Technologies",
                "value": ", ".join(tech[:10]) + ("..." if len(tech) > 10 else ""),
                "inline": False
            })
        
        # Add screenshot if available and enabled
        if config['Discord'].getboolean('send_screenshots') and 'screenshot_path' in discovery_data:
            # Here we would need to upload the image to a hosting service
            # For now, we'll just mention it's available
            data["embeds"][0]["fields"].append({
                "name": "📸 Screenshot",
                "value": "Available locally",
                "inline": False
            })
    
    try:
        response = requests.post(webhook_url, json=data)
        if response.status_code != 204:
            logger.warning(f"Discord webhook returned status code {response.status_code}")
    except Exception as e:
        logger.error(f"Error sending Discord notification: {e}")

# Telegram integration
def send_telegram_notification(bot_token, chat_id, message):
    """Send a notification to Telegram."""
    if not bot_token or not chat_id:
        return
    
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }
    
    try:
        response = requests.post(url, data=data)
        if response.status_code != 200:
            logger.warning(f"Telegram API returned status code {response.status_code}")
    except Exception as e:
        logger.error(f"Error sending Telegram notification: {e}")

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
        parsed = urllib.parse.urlparse(domain)
        domain = parsed.netloc
    
    # Remove www. prefix if present
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Remove trailing slash if present
    if domain.endswith('/'):
        domain = domain[:-1]
    
    return domain.lower()

def get_ip_address(domain, dns_servers=None):
    """Get IP address for a domain using DNS resolution."""
    if dns_servers:
        # Use specific DNS servers if provided
        resolver = dns.resolver.Resolver()
        resolver.nameservers = dns_servers
        try:
            answers = resolver.resolve(domain, 'A')
            return str(answers[0])
        except Exception:
            pass
    
    # Fallback to socket
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def get_random_dns_server():
    """Get a random DNS server from the configured list."""
    global DNS_SERVERS
    if DNS_SERVERS:
        return random.choice(DNS_SERVERS)
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

def check_domain_dns(domain, dns_servers=None):
    """Check if a domain resolves in DNS."""
    try:
        if dns_servers:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = dns_servers
            resolver.resolve(domain, 'A')
        else:
            socket.gethostbyname(domain)
        return True
    except Exception:
        return False

def get_ssl_info(domain, port=443):
    """Get SSL certificate information for a domain."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                
                # Extract useful information
                cert_dict = {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'version': cert['version'],
                    'serial_number': cert.get('serialNumber', 'N/A'),
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter'],
                    'cipher': {
                        'name': cipher[0],
                        'version': cipher[1],
                        'bits': cipher[2]
                    },
                    'alt_names': cert.get('subjectAltName', [])
                }
                
                # Calculate certificate fingerprints
                try:
                    import hashlib
                    cert_dict['fingerprint_sha1'] = hashlib.sha1(cert_bin).hexdigest()
                    cert_dict['fingerprint_sha256'] = hashlib.sha256(cert_bin).hexdigest()
                except Exception:
                    pass
                
                # Extract alternative names
                alt_domains = []
                for alt_name in cert_dict['alt_names']:
                    if alt_name[0] == 'DNS':
                        alt_domains.append(alt_name[1])
                cert_dict['alt_domains'] = alt_domains
                
                # Check certificate validity
                import datetime
                not_after = datetime.datetime.strptime(cert_dict['not_after'], '%b %d %H:%M:%S %Y GMT')
                days_left = (not_after - datetime.datetime.now()).days
                cert_dict['days_left'] = days_left
                cert_dict['is_expired'] = days_left < 0
                
                return cert_dict
    except Exception as e:
        return {"error": str(e)}

def check_wildcard_dns(domain):
    """Check if domain has wildcard DNS records that could give false positives."""
    try:
        random_prefix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=16))
        random_domain = f"{random_prefix}.{domain}"
        
        # Try to resolve the random domain
        if check_domain_dns(random_domain):
            ip_addr = get_ip_address(random_domain)
            if ip_addr:
                logger.warning(f"Wildcard DNS detected for {domain}! IP: {ip_addr}")
                return True, ip_addr
        
        return False, None
    except Exception:
        return False, None

def get_random_user_agent():
    """Get a random user agent string."""
    try:
        ua = UserAgent(verify_ssl=False)
        return ua.random
    except Exception:
        # Fallback user agents if fake-useragent fails
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0'
        ]
        return random.choice(user_agents)

def load_proxies(proxy_file):
    """Load proxy list from file."""
    proxies = []
    if os.path.exists(proxy_file):
        with open(proxy_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    proxies.append(line)
    
    if proxies:
        print(green(f"[+] Loaded {len(proxies)} proxies from {proxy_file}"))
    return proxies

def get_next_proxy():
    """Get the next proxy from the proxy list."""
    global CURRENT_PROXY_INDEX, PROXIES
    
    if not PROXIES:
        return None
    
    with PROXY_LOCK:
        proxy = PROXIES[CURRENT_PROXY_INDEX]
        CURRENT_PROXY_INDEX = (CURRENT_PROXY_INDEX + 1) % len(PROXIES)
    
    return {
        'http': f'http://{proxy}',
        'https': f'http://{proxy}'
    }

def detect_rate_limit(resp):
    """Detect if we're being rate limited based on response."""
    # Common rate limit indicators in headers
    rate_limit_headers = [
        'x-rate-limit-limit',
        'x-rate-limit-remaining',
        'retry-after',
        'ratelimit-limit',
        'ratelimit-remaining',
        'x-ratelimit-limit',
        'x-ratelimit-remaining'
    ]
    
    # Check headers
    for header in rate_limit_headers:
        if header in resp.headers:
            return True
    
    # Check status codes typically used for rate limiting
    if resp.status_code in [429, 418, 403]:
        # Look for rate limit keywords in response body
        limit_keywords = ['rate limit', 'too many requests', 'throttled', 'quota exceeded']
        resp_text = resp.text.lower()
        for keyword in limit_keywords:
            if keyword in resp_text:
                return True
    
    return False

def detect_waf(resp):
    """Detect if a WAF is present based on response headers and content."""
    waf_signatures = {
        'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
        'AWS WAF': ['x-amzn-waf', 'awselb/'],
        'Akamai': ['akamaighost', 'akamai'],
        'Imperva': ['incapsula', 'visitorid'],
        'Sucuri': ['sucuri', 'sucuri-waf'],
        'ModSecurity': ['mod_security', 'modsecurity'],
        'F5 BIG-IP': ['bigip', 'f5'],
        'Wordfence': ['wordfence'],
        'Fortinet': ['fortigate', 'fortiweb'],
        'Fastly': ['fastly', 'x-fastly'],
        'Reblaze': ['reblaze'],
        'DDoS-Guard': ['ddos-guard'],
        'Barracuda': ['barracuda'],
        'Distil': ['distil'],
        'StackPath': ['stackpath']
    }
    
    detected_wafs = []
    
    # Check response headers
    for waf, signatures in waf_signatures.items():
        for signature in signatures:
            # Check headers
            for header, value in resp.headers.items():
                if signature.lower() in header.lower() or signature.lower() in value.lower():
                    detected_wafs.append(waf)
                    break
            
            # Check content if we haven't found a match yet
            if waf not in detected_wafs and signature.lower() in resp.text.lower():
                detected_wafs.append(waf)
    
    # Look for specific patterns in the content
    if 'security' in resp.text.lower() and 'challenge' in resp.text.lower():
        if 'Cloudflare' not in detected_wafs:
            detected_wafs.append('Generic WAF')
    
    return list(set(detected_wafs))  # Remove duplicates

def get_favicon_hash(url):
    """Get the favicon hash for a URL (useful for fingerprinting)."""
    try:
        import mmh3
        import base64
        
        favicon_url = f"{url}/favicon.ico"
        response = requests.get(favicon_url, timeout=5, verify=False)
        
        if response.status_code == 200:
            favicon = base64.b64encode(response.content)
            return mmh3.hash(favicon)
    except Exception:
        pass
    
    return None

def detect_technologies(resp):
    """Detect technologies used by the website based on headers and content."""
    tech_signatures = {
        # CMS
        'WordPress': ['wp-content', 'wp-includes', 'wordpress', 'wp-json'],
        'Joomla': ['joomla', 'mosConfig', 'com_content'],
        'Drupal': ['drupal', 'Drupal.settings', 'drupal.org'],
        'Magento': ['magento', 'Mage.', 'skin/frontend'],
        'Shopify': ['shopify', 'Shopify.theme', '.myshopify.com'],
        'WooCommerce': ['woocommerce', 'WooCommerce', 'wp-content/plugins/woocommerce'],
        'PrestaShop': ['prestashop', 'PrestaShop', '/themes/'],
        'TYPO3': ['typo3', 'TYPO3', 'typo3temp'],
        'Ghost': ['ghost', 'Ghost', 'ghost-sdk'],
        'Blogger': ['blogger', 'blogspot'],
        'Squarespace': ['squarespace', 'static.squarespace.com'],
        'Wix': ['wix', 'wixsite', 'wix.com'],
        
        # Frameworks
        'Laravel': ['laravel', 'Laravel', 'csrf-token'],
        'Django': ['django', 'csrftoken', 'dsrfmiddlewaretoken'],
        'Ruby on Rails': ['rails', '_rails', 'csrf-param'],
        'Express.js': ['express', 'Express', 'x-powered-by: express'],
        'Flask': ['flask', 'Flask', 'werkzeug'],
        'Spring': ['spring', 'Spring', 'org.springframework'],
        'ASP.NET': ['asp.net', 'ASP.NET', '__VIEWSTATE', '.aspx'],
        'ASP.NET MVC': ['asp.net mvc', '__RequestVerificationToken'],
        'Symfony': ['symfony', 'Symfony', '_symfony'],
        
        # JavaScript Frameworks
        'React': ['react', 'React.', 'reactjs', 'react-dom'],
        'Vue.js': ['vue', 'Vue.', 'vuejs', 'vue-router'],
        'Angular': ['angular', 'ng-', 'angular.js', '[ng-'],
        'jQuery': ['jquery', 'jQuery', 'jquery.min.js'],
        'Bootstrap': ['bootstrap', 'Bootstrap', 'bootstrap.min.css'],
        'Tailwind CSS': ['tailwind', 'tailwindcss', 'tailwind.css'],
        'Material UI': ['material-ui', 'materialui', '@material'],
        'Next.js': ['next', 'nextjs', '_next/static'],
        'Nuxt.js': ['nuxt', 'nuxtjs', '_nuxt/'],
        
        # Programming Languages
        'PHP': ['php', 'PHP', '.php', 'X-Powered-By: PHP'],
        'Python': ['python', 'Python', '.py', 'X-Powered-By: Python'],
        'Ruby': ['ruby', 'Ruby', '.rb', 'X-Powered-By: Ruby'],
        'Java': ['java', 'Java', '.jsp', '.java', 'X-Powered-By: JSP'],
        'Node.js': ['node', 'nodejs', 'Node.js', 'X-Powered-By: Node'],
        
        # Web Servers
        'IIS': ['iis', 'Microsoft-IIS', 'X-Powered-By: ASP.NET'],
        'Nginx': ['nginx', 'Nginx', 'Server: nginx'],
        'Apache': ['apache', 'Apache', 'Server: Apache'],
        'Tomcat': ['tomcat', 'Tomcat', 'Apache Tomcat'],
        'LiteSpeed': ['litespeed', 'LiteSpeed', 'Server: LiteSpeed'],
        'Caddy': ['caddy', 'Caddy', 'Server: Caddy'],
        
        # CDN/Security Services
        'Cloudflare': ['cloudflare', 'Cloudflare', 'cf-ray', '__cfduid'],
        'Akamai': ['akamai', 'Akamai', 'X-Akamai-Transformed'],
        'Fastly': ['fastly', 'Fastly', 'x-fastly'],
        'Sucuri': ['sucuri', 'Sucuri', 'X-Sucuri-ID'],
        'Imperva': ['imperva', 'Imperva', 'X-Iinfo'],
        'AWS CloudFront': ['cloudfront', 'CloudFront', 'X-Amz-Cf-Id'],
        
        # Hosting Platforms
        'Heroku': ['heroku', 'Heroku', 'herokucdn.com'],
        'Vercel': ['vercel', 'Vercel', 'vercel-deployment'],
        'Netlify': ['netlify', 'Netlify', 'netlify.app'],
        'GitHub Pages': ['github', 'GitHub Pages', 'github.io'],
        'Firebase': ['firebase', 'Firebase', 'firebaseapp.com'],
        'AWS Elastic Beanstalk': ['elasticbeanstalk', 'aws-eb'],
        
        # Analytics and Marketing
        'Google Analytics': ['google analytics', 'ga.js', 'analytics.js', 'gtag'],
        'Google Tag Manager': ['gtm', 'googletagmanager.com', 'GTM-'],
        'Facebook Pixel': ['facebook pixel', 'connect.facebook.net/en_US/fbevents.js', 'fbq('],
        'HubSpot': ['hubspot', 'hs-script', 'hubspot.com'],
        'Intercom': ['intercom', 'intercomcdn', 'intercom.io'],
        'Hotjar': ['hotjar', 'static.hotjar.com', '_hjSettings'],
        
        # E-commerce
        'Stripe': ['stripe', 'js.stripe.com', 'Stripe.'],
        'PayPal': ['paypal', 'paypalobjects.com', 'checkout.paypal.com'],
        'Shopify Payments': ['shopify payments', 'checkout.shopify.com'],
        
        # Caching/Performance
        'Redis': ['redis', 'Redis', 'X-Redis'],
        'Varnish': ['varnish', 'Varnish', 'X-Varnish'],
        'Memcached': ['memcached', 'Memcached', 'X-Memcached'],
    }
    
    detected_tech = []
    
    # Check headers
    server = resp.headers.get('Server', '')
    if server:
        detected_tech.append(f"Server: {server}")
    
    # Check for common technologies in headers
    for header, value in resp.headers.items():
        for tech, signatures in tech_signatures.items():
            for sig in signatures:
                if sig.lower() in header.lower() or sig.lower() in value.lower():
                    detected_tech.append(tech)
                    break
    
    # Check HTML content
    soup = bs4.BeautifulSoup(resp.text, 'html.parser')
    
    # Check meta tags
    meta_tags = soup.find_all('meta')
    for tag in meta_tags:
        if tag.get('name') == 'generator' and tag.get('content'):
            detected_tech.append(f"Generator: {tag.get('content')}")
    
    # Check for common script patterns
    scripts = soup.find_all('script')
    for script in scripts:
        src = script.get('src', '')
        for tech, signatures in tech_signatures.items():
            if any(sig.lower() in src.lower() for sig in signatures) or \
               any(sig.lower() in str(script.string).lower() if script.string else False for sig in signatures):
                detected_tech.append(tech)
    
    # Check for common CSS patterns
    links = soup.find_all('link')
    for link in links:
        href = link.get('href', '')
        for tech, signatures in tech_signatures.items():
            if any(sig.lower() in href.lower() for sig in signatures):
                detected_tech.append(tech)
    
    # Check HTML classes
    for element in soup.find_all(class_=True):
        classes = ' '.join(element['class'])
        for tech, signatures in tech_signatures.items():
            if any(sig.lower() in classes.lower() for sig in signatures):
                detected_tech.append(tech)
    
    # Return unique technologies
    return list(set(detected_tech))
    # Gather subdomains from various sources
    all_domains = set()
    
    # Load from wordlist
    base_subdomains = load_subdomains(wordlist_path)
    for subdomain in base_subdomains:
        all_domains.add(f"{subdomain}.{target_domain}")
    
    # Use passive reconnaissance if enabled
    if config['Passive'].getboolean('use_passive_sources'):
        passive_subdomains = discover_subdomains_passive(target_domain, config)
        for subdomain in passive_subdomains:
            all_domains.add(subdomain)
    
    # Generate permutations if enabled
    if config['Advanced'].getboolean('subdomain_generation'):
        permutation_patterns = config['Advanced']['permutation_patterns'].split(',')
        for pattern in permutation_patterns:
            pattern = pattern.strip()
            if pattern:
                for domain in list(all_domains):  # Use a copy to avoid modification during iteration
                    for permutation in generate_permutations(domain, [pattern]):
                        all_domains.add(permutation)
    
    # Generate random subdomains if enabled
    if config['Advanced'].getboolean('random_subdomains'):
        try:
            random_count = int(config['Advanced']['random_count'])
            random_subdomains = generate_random_subdomains(target_domain, random_count)
            for subdomain in random_subdomains:
                all_domains.add(subdomain)
        except ValueError:
            logger.error("Invalid random_count in config, skipping random subdomain generation")
    
    # Apply wordlist mutation if enabled
    if config['Advanced'].getboolean('wordlist_mutation'):
        for subdomain in base_subdomains:
            mutated = mutate_wordlist([subdomain], target_domain)
            for mut_domain in mutated:
                all_domains.add(mut_domain)
    
    # Convert set to list and deduplicate
    full_domains = list(all_domains)
    
    # Check for existing results and resume if needed
    if RESUMED_SCAN and FOUND_DOMAINS:
        print(yellow(f"[*] Resuming scan - {len(FOUND_DOMAINS)} domains already found"))
        
        # Remove already found domains from the scan list
        already_checked_domains = set(item['domain'] for item in FOUND_DOMAINS)
        full_domains = [d for d in full_domains if d not in already_checked_domains]
        
        print(green(f"[+] Reduced scan list to {len(full_domains)} remaining domains"))
    
    # Optional: shuffle domains for less predictable scanning pattern
    random.shuffle(full_domains)
    
    TOTAL_SUBDOMAINS = len(full_domains)
    START_TIME = time.time()
    
    print(yellow(f"[*] Starting scan of {TOTAL_SUBDOMAINS} subdomains for {target_domain}..."))
    print(yellow(f"[*] Results will be saved to {report_file}"))
    
    # Write CSV header to report file if not resuming
    if not RESUMED_SCAN:
        with open(report_file, 'w') as f:
            f.write("subdomain,ip_address,status_code,protocol,response_time_ms,server,technologies,waf\n")
    
    # Determine thread count
    try:
        thread_count = int(config['General']['threads'])
    except (KeyError, ValueError):
        # Default to CPU count or 50, whichever is less
        thread_count = min(50, os.cpu_count() * 2 if os.cpu_count() else 50)
    
    print(cyan(f"[*] Using {thread_count} threads"))
    
    try:
        # Use ThreadPoolExecutor for better compatibility
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
    
    # Perform recursive scanning if enabled
    if config['Advanced'].getboolean('recursive_depth') and FOUND_DOMAINS:
        try:
            recursive_depth = int(config['Advanced']['recursive_depth'])
            if recursive_depth > 0:
                # For each found domain, recursively scan
                for domain_data in FOUND_DOMAINS:
                    domain = domain_data['domain']
                    scan_recursively(domain, target_domain, recursive_depth, config, report_file, discord_webhook)
        except ValueError:
            logger.error("Invalid recursive_depth in config, skipping recursive scanning")
    
    # Perform additional analysis on found domains
    if FOUND_DOMAINS:
        print(cyan("\n[*] Performing additional analysis on found domains..."))
        
        # Port scanning
        if config['Analysis'].getboolean('port_scan') and NMAP_AVAILABLE:
            print(yellow("[*] Scanning common ports on discovered domains..."))
            for domain_data in FOUND_DOMAINS:
                ip = domain_data['ip']
                domain = domain_data['domain']
                
                # Skip if IP is already scanned
                if any(d.get('port_scan') for d in FOUND_DOMAINS if d['ip'] == ip):
                    continue
                
                print(f"[*] Scanning ports for {domain} ({ip})...")
                port_results = scan_ports(ip)
                
                if 'error' not in port_results:
                    domain_data['port_scan'] = port_results
                    
                    # Save port scan results
                    ports_dir = Path(f"{TEMP_DIR}/ports")
                    ports_dir.mkdir(exist_ok=True)
                    
                    with open(f"{ports_dir}/{domain.replace('.', '_')}.json", 'w') as f:
                        json.dump(port_results, f, indent=2)
        
        # Vulnerability checking
        if config['Analysis'].getboolean('vuln_check'):
            print(yellow("[*] Checking for common vulnerabilities..."))
            for domain_data in FOUND_DOMAINS:
                domain = domain_data['domain']
                ip = domain_data['ip']
                technologies = domain_data.get('technologies', [])
                
                vulns = check_common_vulnerabilities(domain, ip, technologies)
                
                if vulns:
                    domain_data['vulnerabilities'] = vulns
                    
                    # Print found vulnerabilities
                    print(f"[!] Found {len(vulns)} potential vulnerabilities for {domain}:")
                    for vuln in vulns:
                        severity = vuln['severity']
                        if severity == 'Critical':
                            severity_str = red(severity)
                        elif severity == 'High':
                            severity_str = magenta(severity)
                        elif severity == 'Medium':
                            severity_str = yellow(severity)
                        else:
                            severity_str = blue(severity)
                        
                        print(f"    └─ {vuln['name']} ({severity_str}): {vuln['description']}")
                    
                    # Save vulnerability results
                    vuln_dir = Path(f"{TEMP_DIR}/vulnerabilities")
                    vuln_dir.mkdir(exist_ok=True)
                    
                    with open(f"{vuln_dir}/{domain.replace('.', '_')}.json", 'w') as f:
                        json.dump(vulns, f, indent=2)
        
        # Directory checking
        if config['Analysis'].getboolean('directory_check'):
            print(yellow("[*] Checking for common directories..."))
            for domain_data in FOUND_DOMAINS:
                domain = domain_data['domain']
                
                directories = check_common_directories(domain)
                
                if directories:
                    domain_data['directories'] = directories
                    
                    # Print found directories
                    print(f"[+] Found {len(directories)} accessible directories for {domain}:")
                    for dir_info in directories[:5]:  # Show only the first 5
                        status_code = dir_info['status']
                        if status_code == 200:
                            status_str = green(str(status_code))
                        elif status_code in [401, 403]:
                            status_str = yellow(str(status_code))
                        else:
                            status_str = str(status_code)
                        
                        print(f"    └─ {dir_info['directory']} ({status_str}) - Size: {dir_info['content_length']} bytes")
                    
                    if len(directories) > 5:
                        print(f"    └─ ... and {len(directories) - 5} more")
                    
                    # Save directory results
                    dir_check_dir = Path(f"{TEMP_DIR}/directories")
                    dir_check_dir.mkdir(exist_ok=True)
                    
                    with open(f"{dir_check_dir}/{domain.replace('.', '_')}.json", 'w') as f:
                        json.dump(directories, f, indent=2)
        
        # Subdomain takeover checking
        if config['Advanced'].getboolean('takeover_check'):
            print(yellow("[*] Checking for subdomain takeover vulnerabilities..."))
            for domain_data in FOUND_DOMAINS:
                domain = domain_data['domain']
                
                takeover_result = check_takeover_vulnerability(domain)
                
                if takeover_result.get('vulnerable', False):
                    domain_data['takeover'] = takeover_result
                    
                    # Print takeover vulnerability
                    service = takeover_result.get('service', 'Unknown')
                    print(red(f"[!] Potential subdomain takeover for {domain} ({service})!"))
                    
                    # Save takeover results
                    takeover_dir = Path(f"{TEMP_DIR}/takeover")
                    takeover_dir.mkdir(exist_ok=True)
                    
                    with open(f"{takeover_dir}/{domain.replace('.', '_')}.json", 'w') as f:
                        json.dump(takeover_result, f, indent=2)
    
    # Calculate and print statistics
    elapsed_time = time.time() - START_TIME
    print("\n" + "=" * 60)
    print(green(f"[+] Scan completed!"))
    print(f"[+] Total subdomains checked: {TOTAL_CHECKED}")
    print(f"[+] Found {len(FOUND_DOMAINS)} active subdomains")
    print(f"[+] Elapsed time: {elapsed_time:.2f} seconds")
    print(f"[+] Average speed: {TOTAL_CHECKED / elapsed_time:.2f} domains/second")
    print(f"[+] Results saved to: {report_file}")
    
    # Collect WAFs detected
    all_wafs = set()
    for domain_data in FOUND_DOMAINS:
        if 'waf' in domain_data and domain_data['waf']:
            for waf in domain_data['waf']:
                all_wafs.add(waf)
    
    if all_wafs:
        print(f"[+] WAFs detected: {', '.join(all_wafs)}")
    
    # List top technologies
    all_techs = {}
    for domain_data in FOUND_DOMAINS:
        if 'technologies' in domain_data and domain_data['technologies']:
            for tech in domain_data['technologies']:
                all_techs[tech] = all_techs.get(tech, 0) + 1
    
    if all_techs:
        top_techs = sorted(all_techs.items(), key=lambda x: x[1], reverse=True)[:10]
        print(f"[+] Top technologies: " + ", ".join(f"{tech} ({count})" for tech, count in top_techs))
    
    print("=" * 60)
    
    # Generate summary file
    summary_file = f"Summary_{target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(summary_file, 'w') as f:
        f.write(f"CloudKiller Pro v{VERSION} - Scan Summary\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Target Domain: {target_domain}\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Scan Duration: {elapsed_time:.2f} seconds\n")
        f.write(f"Scan ID: {SCAN_ID}\n\n")
        
        f.write(f"Subdomains Checked: {TOTAL_CHECKED}\n")
        f.write(f"Subdomains Found: {len(FOUND_DOMAINS)}\n")
        f.write(f"Success Rate: {(len(FOUND_DOMAINS) / TOTAL_CHECKED * 100) if TOTAL_CHECKED > 0 else 0:.2f}%\n\n")
        
        f.write("Detected WAFs:\n")
        for waf in sorted(all_wafs):
            f.write(f"- {waf}\n")
        f.write("\n")
        
        f.write("Top Technologies:\n")
        for tech, count in top_techs[:20] if all_techs else []:
            f.write(f"- {tech}: {count}\n")
        f.write("\n")
        
        f.write("Found Subdomains:\n")
        for domain_data in sorted(FOUND_DOMAINS, key=lambda x: x['domain']):
            f.write(f"- {domain_data['domain']} ({domain_data['ip']})\n")
    
    print(green(f"[+] Summary saved to: {summary_file}"))
    
    # Send a final summary to Discord if enabled
    if discord_webhook and config['Discord'].getboolean('enabled') and config['Discord'].getboolean('send_summary') and FOUND_DOMAINS:
        print(cyan("[*] Sending summary to Discord..."))
        
        summary_data = {
            'target_domain': target_domain,
            'total_checked': TOTAL_CHECKED,
            'total_found': len(FOUND_DOMAINS),
            'elapsed_time': elapsed_time,
            'success_rate': (len(FOUND_DOMAINS) / TOTAL_CHECKED * 100) if TOTAL_CHECKED > 0 else 0,
            'wafs': list(all_wafs) if all_wafs else []
        }
        
        send_discord_notification(discord_webhook, summary_data, config, is_summary=True)
    
    # Send summary to Telegram if enabled
    if config['Telegram'].getboolean('enabled') and FOUND_DOMAINS:
        bot_token = config['Telegram']['bot_token']
        chat_id = config['Telegram']['chat_id']
        
        if bot_token and chat_id:
            print(cyan("[*] Sending summary to Telegram..."))
            
            message = f"*CloudKiller Pro - Scan Completed*\n\n"
            message += f"Target: `{target_domain}`\n"
            message += f"Subdomains Found: {len(FOUND_DOMAINS)}\n"
            message += f"Scan Duration: {elapsed_time:.2f} seconds\n\n"
            
            # Add top 5 domains
            if FOUND_DOMAINS:
                message += "*Top findings:*\n"
                for domain_data in sorted(FOUND_DOMAINS, key=lambda x: x.get('status', 0) == 200)[:5]:
                    message += f"• `{domain_data['domain']}` ({domain_data['ip']})\n"
            
            send_telegram_notification(bot_token, chat_id, message)

def check_existing_report(domain):
    """Check if a report already exists for this domain and offer to resume."""
    global RESUMED_SCAN
    
    report_name = f'Report_{domain}.csv'
    
    if os.path.exists(report_name):
        print(yellow(f"[!] A previous report for {domain} exists: {report_name}"))
        try:
            choice = input(yellow("[?] Do you want to (O)verwrite, (A)ppend to it, or (C)ancel? [O/A/C] >> "))
            
            if choice.lower() == 'o':
                return report_name  # Will be overwritten
            elif choice.lower() == 'a':
                # Read found domains from the existing report to prevent rechecking
                RESUMED_SCAN = True
                try:
                    with open(report_name, 'r') as f:
                        next(f)  # Skip header
                        for line in f:
                            parts = line.strip().split(',')
                            if len(parts) >= 2:
                                domain_data = {
                                    'domain': parts[0],
                                    'ip': parts[1],
                                    'status': int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                                    'protocol': parts[3] if len(parts) > 3 else 'http',
                                    'response_time': float(parts[4]) if len(parts) > 4 and parts[4] else 0.0,
                                    'server': parts[5] if len(parts) > 5 else 'Unknown',
                                    'technologies': parts[6].split('|') if len(parts) > 6 and parts[6] else [],
                                    'waf': parts[7].split('|') if len(parts) > 7 and parts[7] else []
                                }
                                FOUND_DOMAINS.append(domain_data)
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
    
    # Clean up temporary files if needed
    # if os.path.exists(TEMP_DIR):
    #     shutil.rmtree(TEMP_DIR)
    
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
    parser = argparse.ArgumentParser(description=f'CloudKiller Pro v{VERSION} - Advanced Subdomain Discovery Tool')
    parser.add_argument('-d', '--domain', help='Target domain')
    parser.add_argument('-w', '--wordlist', help='Path to subdomain wordlist')
    parser.add_argument('-o', '--output', help='Output file name')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads')
    parser.add_argument('--webhook', help='Discord webhook URL')
    parser.add_argument('--config', help='Path to config file')
    parser.add_argument('--passive', action='store_true', help='Use only passive reconnaissance (no active scanning)')
    parser.add_argument('--no-analysis', action='store_true', help='Disable additional analysis')
    parser.add_argument('--proxy', help='Use proxy (format: host:port)')
    parser.add_argument('--version', action='version', version=f'CloudKiller Pro v{VERSION}')
    
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
    
    if args.passive:
        config['Passive']['use_passive_sources'] = 'True'
        config['General']['threads'] = '1'  # Reduce threads for passive mode
        print(yellow("[!] Passive mode enabled - active scanning disabled"))
    
    if args.no_analysis:
        config['Analysis']['port_scan'] = 'False'
        config['Analysis']['vuln_check'] = 'False'
        config['Analysis']['directory_check'] = 'False'
        config['Analysis']['screenshot'] = 'False'
        print(yellow("[!] Additional analysis disabled"))
    
    if args.proxy:
        config['General']['proxy_enabled'] = 'True'
        os.environ['HTTP_PROXY'] = args.proxy
        os.environ['HTTPS_PROXY'] = args.proxy
        print(green(f"[+] Using proxy: {args.proxy}"))
    
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
        print("\n[-] Cloud Killer Pro was closed by user.")
    except Exception as e:
        print(red(f"\n[!] An unexpected error occurred: {str(e)}"))
        logger.exception("Unexpected error")
