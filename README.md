# CloudKiller Pro 3.0

![Banner](https://img.shields.io/badge/CloudKiller-Pro%203.0-brightgreen)
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![WAF Bypass](https://img.shields.io/badge/WAF%20Bypass-Cloudflare%20%7C%20Akamai%20%7C%20AWS-orange)
![Version](https://img.shields.io/badge/Version-3.0.0-informational)
![Stars](https://img.shields.io/badge/Stars-★★★★★-yellow)
![Contributors](https://img.shields.io/badge/Contributors-12-blueviolet)
![Technologies](https://img.shields.io/badge/Technologies-80%2B-success)

## Bypass Cloud Protection - Advanced Subdomain Discovery & Analysis Tool

CloudKiller Pro is an advanced subdomain discovery tool that bypasses common cloud protections. Designed for penetration testers, security researchers, and security professionals, CloudKiller helps you discover hidden or forgotten assets that might represent a potential attack surface for your organization.

![CloudKiller Screenshot](https://github.com/user-attachments/assets/ebd062b3-bbad-457b-810b-89629c419c46)


## 🚀 Key Features

### CloudKiller 2.0
- **Advanced Multithreading**: Run rapid scans with multi-thread support
- **Discord Integration**: Receive real-time notifications when new subdomains are found
- **Robust DNS Validation**: Verify subdomains with different methods (DNS, HTTP, ping)
- **Configuration System**: Easily customize all options via configuration file
- **Real IP Detection**: Bypass cloud protections to find real IP addresses
- **Detailed Reporting**: Output in various formats (CSV, JSON)
- **Color Interface**: Clear visualization of results with cross-platform support
- **Scan Resume**: Ability to resume interrupted scans

### CloudKiller Pro 3.0 (Additional Features)
- **🔍 Passive DNS Resolution**: Uses services like crt.sh, SecurityTrails, dns.bufferover.run, Anubis and others
- **🧠 Dynamic Wordlists**: Intelligent subdomain generation based on patterns
- **🛡️ Advanced WAF/CDN Bypass**: Sophisticated techniques to bypass cloud protections
- **🧩 Origin IP Detection**: Check if a subdomain exposes the true origin IP
- **🧠 Technology Fingerprinting**: Identifies CMS, frameworks, web servers and other technologies (80+ signatures)
- **🔍 Vulnerability Checking**: Automated verification of common vulnerabilities
- **📂 Directory Enumeration**: Automatic search for sensitive paths
- **🤖 Telegram Integration**: Support for Telegram notifications besides Discord
- **🔐 SSL Certificate Analysis**: Extraction of detailed information from SSL certificates
- **🔎 Takeover Verification**: Check for subdomain takeover possibilities
- **⚡ Anti Rate-Limit**: Advanced systems to avoid blocks during scans
- **🗺️ Recursive Scanning**: Scan subdomains of already found subdomains
- **🔄 Advanced Resume**: Improved system to resume interrupted scans
- **🌐 Multiple DNS Support**: Use of multiple DNS servers to avoid blocks
- **📷 Screenshot Capture**: Automatic screenshot capture of discovered domains
- **🔧 Extended Permutations**: Over 100 permutation patterns for subdomain discovery
- **🛑 Advanced Error Handling**: Better handling of errors and timeouts
- **🌗 Dark Mode**: Color interface optimized for dark terminals too
- **🔐 Favicon Analysis**: Identification of sites through favicon hashing
- **🔍 Wildcard DNS Detection**: Detection and management of wildcard domains
- **♻️ Proxy Management**: Proxy rotation support to avoid IP blocks
- **🔍 Integrated WHOIS**: Analysis of domain registration information
- **📊 Advanced Statistics**: Detailed metrics on scans and discoveries
- **📌 JSON Export**: Detailed export of results in JSON format
- **🛠️ Advanced HTTP Detection**: Testing of both HTTP and HTTPS protocols
- **🕵️ Server Header Analysis**: Server and technology detection from HTTP headers
- **🔒 HTTPS/TLS Fingerprinting**: Identification of TLS configurations and certificates

## 📋 Prerequisites

- Python 3.7 or higher
- Internet connection
- Permissions to run pings and HTTP requests

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/next-code-community/CloudKillerPro
cd CloudKillerPro
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make sure you have a wordlist file (`subl.txt`) in the same directory

## 🏃‍♂️ Basic Usage

### Interactive Mode
```bash
python cloudkiller.py
```

### With Parameters
```bash
python cloudkiller.py -d example.com -w wordlist.txt --webhook https://discord.com/api/webhooks/your-webhook-url
```

### Advanced Options
```bash
# Passive Mode (public sources only)
python cloudkiller.py -d example.com --passive

# Scanning with proxy
python cloudkiller.py -d example.com --proxy 127.0.0.1:8080

# Without additional analysis (faster)
python cloudkiller.py -d example.com --no-analysis
```

### All Available Options
```
-d, --domain       Target domain (e.g. example.com)
-w, --wordlist     Path to subdomain wordlist
-o, --output       Output file name
-t, --threads      Number of threads to use
--webhook          Discord webhook URL for notifications
--config           Path to custom configuration file
--passive          Use only passive reconnaissance (no active scanning)
--no-analysis      Disable additional analysis
--proxy            Use proxy (format: host:port)
--version          Show program version
```

## ⚙️ Configuration

CloudKiller Pro uses a configuration file (`cloudkiller2.0.conf`) for advanced settings. You can modify this file to customize the tool's behavior.

### Configuration Sections
- **General**: General settings like threads, timeout, etc.
- **HTTP**: HTTP request configuration
- **Output**: Options for reporting and logging
- **Analysis**: Controls for additional analysis features
- **Passive**: Sources for passive subdomain discovery
- **API_Keys**: API keys for third-party services
- **Discord**: Discord notification configuration
- **Telegram**: Telegram notification configuration
- **Advanced**: Advanced settings like recursive depth

## 📊 Output Example

A generated report file (`Report_example.com.csv`) will have a format like:

```
subdomain,ip_address,status_code,protocol,response_time_ms,server,technologies,waf
mail.example.com,192.168.1.10,200,http,342.5,Apache,PHP|Postfix,Cloudflare
api.example.com,192.168.1.15,403,https,120.8,nginx,Node.js|Express,AWS WAF
dev.example.com,192.168.1.20,200,http,250.3,IIS,ASP.NET|SQL Server,
```

Additionally, CloudKiller Pro generates:
- Detailed JSON reports for each domain
- Summary file with statistics and metrics
- Detailed data on detected technologies and WAFs
- Domain screenshots (if enabled)
- SSL certificate analysis
- WHOIS information
- Port scan results (if enabled)
- Potential vulnerability reports

## 🔍 How It Works

CloudKiller Pro uses a multi-phase approach to discover and analyze subdomains:

1. **Multi-source Enumeration**: Combines wordlists with data from passive sources like crt.sh
2. **Intelligent Generation**: Creates permutations and variants of known subdomains
3. **Multi-method Validation**: Verification through DNS, HTTP/HTTPS and ping
4. **Protection Bypass**: Uses advanced techniques to bypass WAFs and CDNs
5. **In-depth Analysis**: Technology fingerprinting, vulnerability checking, etc.
6. **Recursive Scanning**: Searches for subdomains of already found subdomains
7. **Extended Reporting**: Generates detailed reports and sends real-time notifications

## 🛠️ Detectable Technologies

CloudKiller Pro can detect over 80 different technologies, including:

### CMS
WordPress, Joomla, Drupal, Magento, Shopify, PrestaShop, TYPO3, Ghost, Blogger, Squarespace, Wix

### Frameworks
Laravel, Django, Ruby on Rails, Express.js, Flask, Spring, ASP.NET, ASP.NET MVC, Symfony

### JavaScript Frameworks
React, Vue.js, Angular, jQuery, Bootstrap, Tailwind CSS, Material UI, Next.js, Nuxt.js

### Programming Languages
PHP, Python, Ruby, Java, Node.js

### Web Servers
IIS, Nginx, Apache, Tomcat, LiteSpeed, Caddy

### CDN/Security
Cloudflare, Akamai, Fastly, Sucuri, Imperva, AWS CloudFront

### And many more...

## 🛡️ Bypassable WAFs and CDNs

CloudKiller Pro implements techniques to bypass or detect protections such as:

- Cloudflare
- AWS WAF / CloudFront
- Akamai
- Imperva / Incapsula
- Sucuri
- ModSecurity
- F5 BIG-IP
- Fastly
- Reblaze
- DDoS-Guard
- Barracuda
- Distil Networks
- StackPath
- Wordfence

## 🔒 Ethical Use and Disclaimer

CloudKiller Pro is designed to be used ethically and legally, as part of authorized security assessments. Do not use this tool on systems or domains for which you do not have explicit authorization.

**Disclaimer**: The author assumes no responsibility for the misuse of this tool or for any damage caused by its use. The user is solely responsible for the correct and legal use of CloudKiller Pro.

## 🤝 Contributing

Contributions are welcome! If you want to improve CloudKiller Pro, you can:

1. Fork the repository
2. Create a branch for your feature (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -m 'Added new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Open a Pull Request

## 📜 License

This project is distributed under the MIT license. See the `LICENSE` file for more details.

## 🙏 Acknowledgements

- NC (github.com/next-code-community) - Original creator

## 📞 Contact

For questions, suggestions, or issues, you can:
- Open an issue on GitHub
- Contact the author via GitHub
