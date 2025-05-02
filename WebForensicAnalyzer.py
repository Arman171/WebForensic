#!/usr/bin/env python3
# WebForensicAnalyzer.py - Advanced Web Reconnaissance Tool
# A comprehensive tool for website forensic analysis and information gathering

import argparse
import concurrent.futures
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
from datetime import datetime
from typing import Dict, List, Set, Tuple, Union, Optional

try:
    # Core libraries for web scraping and analysis
    import dns.resolver
    import requests
    import whois
    from bs4 import BeautifulSoup
    from colorama import Fore, Style, init
    from urllib3.exceptions import InsecureRequestWarning
    from tqdm import tqdm

    # Optional libraries for enhanced functionality
    try:
        import nmap
        NMAP_AVAILABLE = True
    except ImportError:
        NMAP_AVAILABLE = False

    try:
        from shodan import Shodan
        SHODAN_AVAILABLE = True
    except ImportError:
        SHODAN_AVAILABLE = False

    # Suppress insecure request warnings
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    # Initialize colorama
    init(autoreset=True)
except ImportError as e:
    missing_module = str(e).split("'")[1]
    print(f"[ERROR] Missing required module: {missing_module}")
    print(f"Please install the required dependencies: pip install -r requirements.txt")
    sys.exit(1)

# Global Constants
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0",
}

# Regex patterns
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
PHONE_PATTERN = r'(\+\d{1,3}[-\.\s]?)?(\(?\d{3}\)?[-\.\s]?)?\d{3}[-\.\s]?\d{4}'
IP_PATTERN = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
SOCIAL_MEDIA_PATTERNS = {
    'Facebook': r'facebook\.com/([^/"\'\s]+)',
    'Twitter': r'twitter\.com/([^/"\'\s]+)',
    'LinkedIn': r'linkedin\.com/([^/"\'\s]+)',
    'Instagram': r'instagram\.com/([^/"\'\s]+)',
    'YouTube': r'youtube\.com/([^/"\'\s]+)',
    'GitHub': r'github\.com/([^/"\'\s]+)',
}

class WebForensicAnalyzer:
    """A comprehensive forensic analysis tool for websites."""
    
    def __init__(self, url: str, depth: int = 1, timeout: int = DEFAULT_TIMEOUT,
                 output: str = None, verbose: bool = False, delay: float = 0.5,
                 user_agent: str = DEFAULT_USER_AGENT, shodan_api_key: str = None,
                 proxy: str = None, headers: Dict = None, cookies: Dict = None):
        """
        Initialize the WebForensicAnalyzer with the target URL and configuration.
        
        Args:
            url: Target URL to analyze
            depth: Crawling depth (default: 1)
            timeout: Request timeout in seconds (default: 10)
            output: Output file path for results
            verbose: Enable verbose output
            delay: Delay between requests in seconds (default: 0.5)
            user_agent: Custom User-Agent string
            shodan_api_key: Shodan API key for enhanced reconnaissance
            proxy: Proxy URL (e.g., http://127.0.0.1:8080)
            headers: Custom HTTP headers
            cookies: Custom cookies for requests
        """
        # Parse and normalize URL
        self.original_url = url
        self.url = self._normalize_url(url)
        self.base_url = self._get_base_url(self.url)
        self.domain = urllib.parse.urlparse(self.url).netloc
        
        # Remove 'www.' if present
        if self.domain.startswith('www.'):
            self.root_domain = self.domain[4:]
        else:
            self.root_domain = self.domain
            
        # Configuration
        self.depth = max(1, min(depth, 3))  # Limit depth between 1-3
        self.timeout = timeout
        self.output = output
        self.verbose = verbose
        self.delay = delay
        self.user_agent = user_agent
        self.shodan_api_key = shodan_api_key
        self.proxy = proxy
        
        # Request configuration
        self.headers = headers or {
            **DEFAULT_HEADERS,
            "User-Agent": self.user_agent
        }
        self.cookies = cookies or {}
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        
        # Initialize results storage
        self.results = {
            "metadata": {
                "target": self.url,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_duration": None,
            },
            "domain_info": {},
            "server_info": {},
            "technologies": {},
            "contacts": {
                "emails": set(),
                "phones": set(),
                "social_media": {},
            },
            "security_info": {},
            "content": {
                "pages": {},
                "forms": [],
                "links": {
                    "internal": set(),
                    "external": set(),
                    "resources": set(),
                },
                "data_leaks": [],
            },
        }
        
        # Visited pages tracking
        self.visited_urls = set()
        self.urls_to_visit = set([self.url])

        # Initialize Shodan API if available
        self.shodan_client = None
        if SHODAN_AVAILABLE and self.shodan_api_key:
            try:
                self.shodan_client = Shodan(self.shodan_api_key)
                if self.verbose:
                    self._print_verbose(f"Shodan API initialized successfully", Fore.GREEN)
            except Exception as e:
                self._print_verbose(f"Failed to initialize Shodan API: {str(e)}", Fore.RED)
        
        # Initialize nmap scanner if available
        self.nmap_scanner = None
        if NMAP_AVAILABLE:
            try:
                self.nmap_scanner = nmap.PortScanner()
                if self.verbose:
                    self._print_verbose(f"Nmap scanner initialized successfully", Fore.GREEN)
            except Exception as e:
                self._print_verbose(f"Failed to initialize Nmap scanner: {str(e)}", Fore.RED)

    def _normalize_url(self, url: str) -> str:
        """
        Normalize the URL by adding scheme if missing and handling trailing slashes.
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL
        """
        if not url:
            return ""
            
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Parse URL
        parsed = urllib.parse.urlparse(url)
        
        # Ensure netloc exists
        if not parsed.netloc:
            return ""
            
        # Reconstruct URL
        return urllib.parse.urlunparse(parsed)

    def _get_base_url(self, url: str) -> str:
        """
        Extract the base URL (scheme + domain) from a URL.
        
        Args:
            url: Full URL
            
        Returns:
            Base URL (scheme + domain)
        """
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _print_banner(self):
        """Print the tool banner."""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
{Fore.CYAN}║ {Fore.YELLOW}WebForensicAnalyzer {Style.RESET_ALL}- {Fore.GREEN}Advanced Website Reconnaissance Tool{Fore.CYAN} ║
{Fore.CYAN}╚══════════════════════════════════════════════════════════╝
{Fore.WHITE}Target: {Fore.GREEN}{self.url}
{Fore.WHITE}Started at: {Fore.GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{Fore.WHITE}Analysis depth: {Fore.GREEN}{self.depth}
{Style.RESET_ALL}"""
        print(banner)

    def _print_section(self, title: str):
        """
        Print a section header.
        
        Args:
            title: Section title
        """
        print(f"\n{Fore.CYAN}[+] {Fore.WHITE}{title}{Fore.CYAN} {'-' * (50 - len(title))}{Style.RESET_ALL}")

    def _print_verbose(self, message: str, color: str = Fore.BLUE):
        """
        Print verbose messages if verbose mode is enabled.
        
        Args:
            message: Message to print
            color: Message color
        """
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"{Fore.MAGENTA}[{timestamp}] {color}{message}{Style.RESET_ALL}")

    def _print_error(self, message: str):
        """
        Print error messages.
        
        Args:
            message: Error message
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.MAGENTA}[{timestamp}] {Fore.RED}[ERROR] {message}{Style.RESET_ALL}")

    def _make_request(self, url: str, method: str = "GET", 
                      data: Dict = None, allow_redirects: bool = True) -> Optional[requests.Response]:
        """
        Make an HTTP request with error handling and rate limiting.
        
        Args:
            url: URL to request
            method: HTTP method (default: GET)
            data: POST data if method is POST
            allow_redirects: Whether to follow redirects
            
        Returns:
            Response object if successful, None otherwise
        """
        # Rate limiting
        time.sleep(self.delay)
        
        try:
            if method.upper() == "GET":
                response = requests.get(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxies,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=allow_redirects
                )
            elif method.upper() == "POST":
                response = requests.post(
                    url,
                    data=data,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxies,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=allow_redirects
                )
            else:
                self._print_error(f"Unsupported HTTP method: {method}")
                return None
                
            self._print_verbose(f"Request to {url} completed with status {response.status_code}")
            return response
            
        except requests.exceptions.ConnectionError:
            self._print_error(f"Connection error when accessing {url}")
        except requests.exceptions.Timeout:
            self._print_error(f"Request timeout when accessing {url}")
        except requests.exceptions.RequestException as e:
            self._print_error(f"Request error when accessing {url}: {str(e)}")
        except Exception as e:
            self._print_error(f"Unexpected error when accessing {url}: {str(e)}")
            
        return None

    def analyze(self) -> Dict:
        """
        Run the complete website analysis.
        
        Returns:
            Analysis results dictionary
        """
        start_time = time.time()
        
        self._print_banner()
        
        # Perform domain reconnaissance
        self._print_section("Domain Information")
        self._gather_domain_info()
        
        # Gather server information
        self._print_section("Server Information")
        self._gather_server_info()
        
        # Check Shodan data if available
        if self.shodan_client:
            self._print_section("Shodan Intelligence")
            self._gather_shodan_info()
        
        # Perform port scanning if available
        if self.nmap_scanner:
            self._print_section("Port Scanning")
            self._scan_ports()
        
        # Crawl website with specified depth
        self._print_section("Website Crawling")
        self._crawl_website()
        
        # Analyze security headers
        self._print_section("Security Analysis")
        self._analyze_security()
        
        # Record scan duration
        end_time = time.time()
        duration = end_time - start_time
        self.results["metadata"]["scan_duration"] = f"{duration:.2f} seconds"
        
        self._print_section("Scan Summary")
        self._print_summary()
        
        # Save results if output file specified
        if self.output:
            self._save_results()
        
        return self._prepare_return_results()

    def _gather_domain_info(self):
        """Gather domain registration and DNS information."""
        print(f"Gathering information for domain: {self.domain}")
        
        # Resolve IP address
        try:
            ip_address = socket.gethostbyname(self.domain)
            self.results["domain_info"]["ip_address"] = ip_address
            print(f"IP Address: {Fore.GREEN}{ip_address}{Style.RESET_ALL}")
        except socket.gaierror:
            self._print_error(f"Could not resolve domain {self.domain}")
            self.results["domain_info"]["ip_address"] = None
        
        # Get WHOIS information
        try:
            whois_info = whois.whois(self.domain)
            
            # Extract relevant WHOIS data
            whois_data = {}
            for key in ['registrar', 'creation_date', 'expiration_date', 'updated_date', 
                         'name_servers', 'status', 'emails', 'registrant_country']:
                if hasattr(whois_info, key) and getattr(whois_info, key):
                    value = getattr(whois_info, key)
                    
                    # Handle datetime objects and lists
                    if isinstance(value, (list, tuple)):
                        if value and isinstance(value[0], datetime):
                            value = str(value[0])
                        else:
                            value = list(value)
                    elif isinstance(value, datetime):
                        value = str(value)
                        
                    whois_data[key] = value
            
            self.results["domain_info"]["whois"] = whois_data
            
            # Display key WHOIS information
            if 'registrar' in whois_data:
                print(f"Registrar: {Fore.GREEN}{whois_data['registrar']}{Style.RESET_ALL}")
            if 'creation_date' in whois_data:
                print(f"Creation Date: {Fore.GREEN}{whois_data['creation_date']}{Style.RESET_ALL}")
            if 'expiration_date' in whois_data:
                print(f"Expiration Date: {Fore.GREEN}{whois_data['expiration_date']}{Style.RESET_ALL}")
            
            # Extract contact emails from WHOIS if available
            if 'emails' in whois_data and whois_data['emails']:
                emails = whois_data['emails']
                if isinstance(emails, str):
                    emails = [emails]
                for email in emails:
                    self.results["contacts"]["emails"].add(email)
                    
        except Exception as e:
            self._print_error(f"Failed to retrieve WHOIS information: {str(e)}")
            self.results["domain_info"]["whois"] = {}

        # Get DNS records
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                records = [str(answer) for answer in answers]
                dns_records[record_type] = records
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                dns_records[record_type] = []
            except Exception as e:
                self._print_error(f"Error retrieving {record_type} records: {str(e)}")
                dns_records[record_type] = []
        
        self.results["domain_info"]["dns_records"] = dns_records
        
        # Display key DNS records
        for record_type in ['A', 'MX', 'NS']:
            if record_type in dns_records and dns_records[record_type]:
                records = dns_records[record_type]
                print(f"{record_type} Records: {Fore.GREEN}{', '.join(records[:3])}")
                if len(records) > 3:
                    print(f"{' ' * 14}{Fore.GREEN}+ {len(records) - 3} more{Style.RESET_ALL}")

    def _gather_server_info(self):
        """Gather server information from HTTP headers."""
        print(f"Gathering server information...")
        
        response = self._make_request(self.url)
        if not response:
            self._print_error("Failed to connect to server")
            return
            
        # Extract server headers
        headers = dict(response.headers)
        server_info = {}
        
        important_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime',
            'X-Generator', 'X-Drupal-Cache', 'X-Varnish', 'via',
            'X-Wordpress-Cache', 'X-Shopify-Stage'
        ]
        
        for header in important_headers:
            if header in headers:
                server_info[header] = headers[header]
                print(f"{header}: {Fore.GREEN}{headers[header]}{Style.RESET_ALL}")
        
        # Get SSL/TLS information for HTTPS
        if self.url.startswith('https://'):
            try:
                parsed_url = urllib.parse.urlparse(self.url)
                hostname = parsed_url.netloc
                port = parsed_url.port or 443
                
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        ssl_info = {
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'subject': dict(x[0] for x in cert['subject']),
                            'version': cert['version'],
                            'serialNumber': cert['serialNumber'],
                            'notBefore': cert['notBefore'],
                            'notAfter': cert['notAfter'],
                        }
                        
                        server_info['ssl_certificate'] = ssl_info
                        
                        print(f"SSL Issuer: {Fore.GREEN}{ssl_info['issuer'].get('organizationName', 'Unknown')}{Style.RESET_ALL}")
                        print(f"SSL Expires: {Fore.GREEN}{ssl_info['notAfter']}{Style.RESET_ALL}")
                
            except Exception as e:
                self._print_error(f"Failed to retrieve SSL information: {str(e)}")
                server_info['ssl_certificate'] = None
        
        self.results["server_info"] = server_info
        
        # Detect technologies from response
        self._detect_technologies(response)

    def _detect_technologies(self, response):
        """
        Detect web technologies used by the website.
        
        Args:
            response: HTTP response object
        """
        if not response or not response.text:
            return
            
        technologies = {}
        
        # Server and framework detection from headers
        headers = dict(response.headers)
        
        # Check for web server
        if 'Server' in headers:
            technologies['web_server'] = headers['Server']
        
        # Check for common frameworks
        if 'X-Powered-By' in headers:
            technologies['framework'] = headers['X-Powered-By']
        
        # Content-Type detection
        if 'Content-Type' in headers:
            technologies['content_type'] = headers['Content-Type']
        
        # Check HTML content for common technology signatures
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for JavaScript frameworks
        js_frameworks = []
        script_tags = soup.find_all('script')
        
        framework_patterns = {
            'jQuery': r'jquery(?:\.min)?\.js',
            'React': r'react(?:\.min)?\.js|react-dom',
            'Vue.js': r'vue(?:\.min)?\.js',
            'Angular': r'angular(?:\.min)?\.js',
            'Bootstrap': r'bootstrap(?:\.min)?\.js',
            'Lodash': r'lodash(?:\.min)?\.js',
            'Modernizr': r'modernizr(?:\.min)?\.js',
        }
        
        for script in script_tags:
            src = script.get('src', '')
            for framework, pattern in framework_patterns.items():
                if re.search(pattern, src, re.IGNORECASE):
                    js_frameworks.append(framework)
        
        if js_frameworks:
            technologies['javascript_frameworks'] = list(set(js_frameworks))
        
        # Check for meta generator tag
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            technologies['generator'] = meta_generator.get('content')
        
        # Check for CMS signatures
        cms_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
            'Joomla': ['com_content', 'com_users', 'Joomla!'],
            'Drupal': ['Drupal.settings', 'drupal-core'],
            'Magento': ['Mage.', 'magento'],
            'Shopify': ['Shopify.', 'cdn.shopify.com'],
            'Wix': ['wix.com', 'wixsite.com'],
            'Squarespace': ['squarespace.com', 'static.squarespace.com'],
        }
        
        detected_cms = []
        html_content = response.text.lower()
        
        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if pattern.lower() in html_content:
                    detected_cms.append(cms)
                    break
        
        if detected_cms:
            technologies['cms'] = list(set(detected_cms))
        
        # Analytics and tracking tools
        analytics_patterns = {
            'Google Analytics': ['ga\\.js', 'analytics\\.js', 'gtag', 'googletagmanager'],
            'Google Tag Manager': ['googletagmanager\\.com'],
            'Facebook Pixel': ['connect\\.facebook\\.net', 'fbq\\('],
            'HubSpot': ['js\\.hs-scripts\\.com', 'hs-analytics'],
            'Hotjar': ['static\\.hotjar\\.com', 'hjSetting'],
            'Matomo/Piwik': ['matomo\\.js', 'piwik\\.js'],
        }
        
        detected_analytics = []
        
        for tool, patterns in analytics_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    detected_analytics.append(tool)
                    break
        
        if detected_analytics:
            technologies['analytics'] = list(set(detected_analytics))
        
        self.results["technologies"] = technologies
        
        # Print detected technologies
        if technologies:
            print(f"\nDetected Technologies:")
            for category, tech in technologies.items():
                if tech:
                    if isinstance(tech, list):
                        tech_str = ', '.join(tech)
                    else:
                        tech_str = tech
                    print(f"  {category.replace('_', ' ').title()}: {Fore.GREEN}{tech_str}{Style.RESET_ALL}")

    def _gather_shodan_info(self):
        """Gather information from Shodan API if available."""
        if not self.shodan_client:
            return
            
        ip = self.results["domain_info"].get("ip_address")
        if not ip:
            self._print_error("No IP address available for Shodan lookup")
            return
            
        print(f"Gathering Shodan intelligence for IP: {ip}")
        
        try:
            shodan_data = self.shodan_client.host(ip)
            
            # Extract relevant information
            shodan_info = {
                "last_update": shodan_data.get("last_update", ""),
                "ports": shodan_data.get("ports", []),
                "country": shodan_data.get("country_name", ""),
                "city": shodan_data.get("city", ""),
                "isp": shodan_data.get("isp", ""),
                "org": shodan_data.get("org", ""),
                "hostnames": shodan_data.get("hostnames", []),
                "vulnerabilities": shodan_data.get("vulns", []),
            }
            
            # Display key Shodan information
            print(f"Open Ports: {Fore.GREEN}{', '.join(map(str, shodan_info['ports'][:10]))}")
            if len(shodan_info['ports']) > 10:
                print(f"{' ' * 12}{Fore.GREEN}+ {len(shodan_info['ports']) - 10} more{Style.RESET_ALL}")
                
            if shodan_info["org"]:
                print(f"Organization: {Fore.GREEN}{shodan_info['org']}{Style.RESET_ALL}")
                
            if shodan_info["country"]:
                location = f"{shodan_info['country']}"
                if shodan_info["city"]:
                    location += f", {shodan_info['city']}"
                print(f"Location: {Fore.GREEN}{location}{Style.RESET_ALL}")
                
            if shodan_info["vulnerabilities"]:
                print(f"Vulnerabilities: {Fore.RED}{len(shodan_info['vulnerabilities'])}{Style.RESET_ALL}")
                
            self.results["server_info"]["shodan"] = shodan_info
            
        except Exception as e:
            self._print_error(f"Failed to retrieve Shodan information: {str(e)}")
            self.results["server_info"]["shodan"] = {}

    def _scan_ports(self):
        """Perform port scanning if Nmap is available."""
        if not self.nmap_scanner:
            return
            
        ip = self.results["domain_info"].get("ip_address")
        if not ip:
            self._print_error("No IP address available for port scanning")
            return
            
        # Define ports to scan
        common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
        
        print(f"Scanning common ports on {ip} (this may take a while)...")
        
        try:
            # Scan only the most common ports
            self.nmap_scanner.scan(ip, ports=common_ports, arguments='-sV --script=banner -T4')
            
            port_info = {}
            if ip in self.nmap_scanner.all_hosts():
                for proto in self.nmap_scanner[ip].all_protocols():
                    for port in self.nmap_scanner[ip][proto]:
                        service = self.nmap_scanner[ip][proto][port]
                        port_info[port] = {
                            "state": service["state"],
                            "service": service["name"],
                            "product": service.get("product", ""),
                            "version": service.get("version", ""),
                        }
            
            self.results["server_info"]["ports"] = port_info
            
            # Display open ports
            open_ports = {p: info for p, info in port_info.items() if info["state"] == "open"}
            if open_ports:
                print(f"Open ports:")
                for port, info in open_ports.items():
                    service_str = f"{info['service']}"
                    if info["product"]:
                        service_str += f" ({info['product']})"
                        if info["version"]:
                            service_str += f" {info['version']}"
                    print(f"  {Fore.GREEN}Port {port}: {service_str}{Style.RESET_ALL}")
            else:
                print(f"No open ports found on common port ranges")
                
        except Exception as e:
            self._print_error(f"Port scanning failed: {str(e)}")
            self.results["server_info"]["ports"] = {}

    def _crawl_website(self):
        """Crawl the website to the specified depth."""
        print(f"Crawling website with depth {self.depth}...")
        
        current_depth = 0
        while current_depth < self.depth and self.urls_to_visit:
            urls_at_current_depth = list(self.urls_to_visit)
            self.urls_to_visit = set()
            
            print(f"Crawling depth {current_depth + 1}/{self.depth} ({len(urls_at_current_depth)} URLs)...")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self._crawl_page, url) for url in urls_at_current_depth]
                
                # Wait for all futures to complete with progress bar
                for _ in tqdm(concurrent.futures.as_completed(futures), total=len(futures), 
                              desc=f"Crawling pages", unit="page"):
                    pass
                    
            current_depth += 1
    
    def _crawl_page(self, url: str):
        """
        Crawl a single page, extract information, and find links.
        
        Args:
            url: URL to crawl
        """
        if url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        
        # Make the request
        response = self._make_request(url)
        if not response or not response.text:
            return
            
        # Parse HTML
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
        except Exception as e:
            self._print_error(f"Failed to parse HTML from {url}: {str(e)}")
            return
            
        # Store page information
        page_info = {
            "url": url,
            "title": soup.title.string if soup.title else "No Title",
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type", ""),
            "length": len(response.text),
        }
        
        self.results["content"]["pages"][url] = page_info
        
        # Extract contact information
        self._extract_contacts(url, response.text)
        
        # Extract forms
        self._extract_forms(url, soup)
        
        # Find links
        self._extract_links(url, soup)
        
        # Check for potential data leaks
        self._check_data_leaks(url, response.text)
    
    def _extract_contacts(self, url: str, html_content: str):
        """
        Extract contact information from HTML content.
        
        Args:
            url: Source URL
            html_content: HTML content
        """
        # Extract emails
        emails = set(re.findall(EMAIL_PATTERN, html_content))
        for email in emails:
            if self._is_valid_email(email) and email.split('@')[1].lower() in self.root_domain.lower():
                self.results["contacts"]["emails"].add(email)
        
        # Extract phone numbers
        phones = set(re.findall(PHONE_PATTERN, html_content))
        for phone in phones:
            if phone and phone[0]:  # Only add non-empty matches
                # Clean up phone number
                clean_phone = re.sub(r'[^\d+]', '', phone[0])
                if len(clean_phone) >= 7:  # Minimum valid phone length
                    self.results["contacts"]["phones"].add(clean_phone)
        
        # Extract social media profiles
        for platform, pattern in SOCIAL_MEDIA_PATTERNS.items():
            matches = re.findall(pattern, html_content)
            if matches:
                if platform not in self.results["contacts"]["social_media"]:
                    self.results["contacts"]["social_media"][platform] = set()
                for match in matches:
                    self.results["contacts"]["social_media"][platform].add(match)
    
    def _is_valid_email(self, email: str) -> bool:
        """
        Check if an email address seems valid.
        
        Args:
            email: Email address to check
            
        Returns:
            True if email seems valid, False otherwise
        """
        if not email or '@' not in email:
            return False
            
        # Simple validation
        parts = email.split('@')
        if len(parts) != 2:
            return False
            
        local_part, domain = parts
        
        # Check local part
        if not local_part or len(local_part) > 64:
            return False
            
        # Check domain
        if not domain or '.' not in domain:
            return False
            
        return True
    
    def _extract_forms(self, url: str, soup: BeautifulSoup):
        """
        Extract forms from HTML.
        
        Args:
            url: Source URL
            soup: BeautifulSoup object
        """
        forms = soup.find_all('form')
        
        for form in forms:
            form_info = {
                "page_url": url,
                "action": form.get('action', ''),
                "method": form.get('method', 'get').upper(),
                "inputs": []
            }
            
            # Extract form inputs
            inputs = form.find_all(['input', 'select', 'textarea'])
            for input_field in inputs:
                input_type = input_field.name
                if input_type == 'input':
                    input_type = input_field.get('type', 'text')
                    
                input_info = {
                    "type": input_type,
                    "name": input_field.get('name', ''),
                    "id": input_field.get('id', ''),
                    "required": input_field.has_attr('required'),
                }
                
                form_info["inputs"].append(input_info)
            
            self.results["content"]["forms"].append(form_info)
    
    def _extract_links(self, url: str, soup: BeautifulSoup):
        """
        Extract links from HTML.
        
        Args:
            url: Source URL
            soup: BeautifulSoup object
        """
        base_url = self.base_url
        parsed_url = urllib.parse.urlparse(url)
        current_path = parsed_url.path
        
        # Extract all links
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link.get('href', '')
            
            # Skip empty links and anchors
            if not href or href.startswith('#') or href.startswith('javascript:'):
                continue
                
            # Normalize link
            if href.startswith('/'):
                # Absolute path
                full_url = f"{base_url}{href}"
            elif href.startswith(('http://', 'https://')):
                # Full URL
                full_url = href
            else:
                # Relative path
                path_parts = current_path.split('/')
                if not current_path.endswith('/'):
                    path_parts.pop()  # Remove file part
                new_path = '/'.join(path_parts) + '/' + href
                full_url = f"{base_url}{new_path}"
            
            # Normalize and clean URL
            try:
                parsed_link = urllib.parse.urlparse(full_url)
                # Remove fragments
                clean_url = urllib.parse.urlunparse((
                    parsed_link.scheme,
                    parsed_link.netloc,
                    parsed_link.path,
                    parsed_link.params,
                    parsed_link.query,
                    ''  # No fragment
                ))
            except Exception:
                continue
            
            # Determine link type
            if self.domain in parsed_link.netloc:
                # Internal link
                self.results["content"]["links"]["internal"].add(clean_url)
                # Add to crawl queue if not visited
                if clean_url not in self.visited_urls:
                    self.urls_to_visit.add(clean_url)
            else:
                # External link
                self.results["content"]["links"]["external"].add(clean_url)
                
        # Extract resource links (images, scripts, stylesheets, etc.)
        resource_tags = {
            'img': 'src',
            'script': 'src',
            'link': 'href',
            'video': 'src',
            'audio': 'src',
            'source': 'src',
            'iframe': 'src',
        }
        
        for tag, attr in resource_tags.items():
            elements = soup.find_all(tag, attrs={attr: True})
            
            for element in elements:
                src = element.get(attr, '')
                
                # Skip empty and data URIs
                if not src or src.startswith('data:'):
                    continue
                    
                # Normalize link
                if src.startswith('/'):
                    # Absolute path
                    full_url = f"{base_url}{src}"
                elif src.startswith(('http://', 'https://')):
                    # Full URL
                    full_url = src
                else:
                    # Relative path
                    path_parts = current_path.split('/')
                    if not current_path.endswith('/'):
                        path_parts.pop()  # Remove file part
                    new_path = '/'.join(path_parts) + '/' + src
                    full_url = f"{base_url}{new_path}"
                
                self.results["content"]["links"]["resources"].add(full_url)
    
    def _check_data_leaks(self, url: str, html_content: str):
        """
        Check for potential data leaks in HTML content.
        
        Args:
            url: Source URL
            html_content: HTML content
        """
        # Look for common sensitive patterns
        sensitive_patterns = {
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'API Key': r'[a-zA-Z0-9]{32,45}',
            'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
            'Private Key': r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
            'Password Field': r'<input[^>]*type=["\']password["\'][^>]*>',
            'Database Connection': r'mysqli?_connect\s*\(',
            'IP Address': IP_PATTERN,
            'Internal Path': r'[\'"/](?:/[a-zA-Z0-9_.-]+){3,}(?:/[a-zA-Z0-9_.-]+)*[\'"]',
        }
        
        for name, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, html_content)
            
            if matches:
                # Filter out common false positives
                filtered_matches = []
                if name == 'API Key':
                    # Filter out common tokens that match the pattern but are not API keys
                    filtered_matches = [m for m in matches if not re.match(r'^[a-f0-9]{32,40}$', m)]
                elif name == 'IP Address':
                    # Filter out common private IP ranges
                    filtered_matches = [m for m in matches if not (
                        m.startswith('127.') or
                        m.startswith('10.') or
                        m.startswith('192.168.') or
                        re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', m)
                    )]
                elif name == 'Internal Path':
                    # Filter out common web paths
                    common_paths = ['/wp-', '/js/', '/css/', '/images/', '/static/', '/assets/']
                    filtered_matches = [m for m in matches if not any(p in m for p in common_paths)]
                else:
                    filtered_matches = matches
                
                # Add unique matches
                for match in set(filtered_matches):
                    leak = {
                        "type": name,
                        "url": url,
                        "pattern": pattern,
                        "context": self._get_context(html_content, match, 20),
                    }
                    
                    self.results["content"]["data_leaks"].append(leak)
    
    def _get_context(self, content: str, text: str, chars: int = 20) -> str:
        """
        Get context around a string in content.
        
        Args:
            content: Full content
            text: Text to find context for
            chars: Number of characters around the text
            
        Returns:
            Context string
        """
        try:
            index = content.find(text)
            if index == -1:
                return ""
                
            start = max(0, index - chars)
            end = min(len(content), index + len(text) + chars)
            
            context = content[start:end].replace('\n', ' ').strip()
            
            # Highlight the text
            highlighted = context.replace(text, f"[{text}]")
            
            return highlighted
        except Exception:
            return ""

    def _analyze_security(self):
        """Analyze security aspects of the website."""
        print(f"Performing security analysis...")
        
        # Get main page response
        response = self._make_request(self.url)
        if not response:
            self._print_error("Failed to analyze security headers")
            return
            
        security_info = {}
        
        # Check security headers
        headers = dict(response.headers)
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'Content-Security-Policy': 'Missing CSP header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
            'Referrer-Policy': 'Missing Referrer-Policy header',
            'Permissions-Policy': 'Missing Permissions-Policy header',
            'Cache-Control': 'Missing Cache-Control header',
        }
        
        missing_headers = []
        for header, message in security_headers.items():
            if header not in headers:
                missing_headers.append(header)
        
        security_info['missing_security_headers'] = missing_headers
        
        # Check for HTTPS
        is_https = self.url.startswith('https://')
        security_info['https'] = is_https
        
        # Check for mixed content
        if is_https and response.text:
            mixed_content = False
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for HTTP resources on HTTPS page
            for tag, attr in [('img', 'src'), ('script', 'src'), ('link', 'href'),
                              ('iframe', 'src'), ('audio', 'src'), ('video', 'src')]:
                for element in soup.find_all(tag, attrs={attr: True}):
                    src = element.get(attr, '')
                    if src.startswith('http:'):
                        mixed_content = True
                        break
            
            security_info['mixed_content'] = mixed_content
        
        # Check for open redirects in links
        open_redirects = []
        for link in self.results["content"]["links"]["internal"]:
            parsed = urllib.parse.urlparse(link)
            params = urllib.parse.parse_qs(parsed.query)
            
            redirect_params = ['url', 'redirect', 'redirect_to', 'return', 'return_url',
                             'goto', 'next', 'redir', 'target', 'destination', 'link']
                             
            for param in redirect_params:
                if param in params:
                    redirect_value = params[param][0]
                    if redirect_value.startswith(('http://', 'https://')):
                        open_redirects.append({
                            'url': link,
                            'param': param,
                            'value': redirect_value
                        })
        
        security_info['potential_open_redirects'] = open_redirects
        
        # Check for forms without CSRF protection
        csrf_missing_forms = []
        for form in self.results["content"]["forms"]:
            if form["method"] == "POST":
                # Check if form has CSRF token
                has_csrf = False
                csrf_fields = ['csrf', 'token', 'xsrf', 'nonce']
                
                for input_field in form["inputs"]:
                    field_name = input_field["name"].lower()
                    if any(csrf in field_name for csrf in csrf_fields):
                        has_csrf = True
                        break
                
                if not has_csrf:
                    csrf_missing_forms.append(form["page_url"])
        
        security_info['forms_without_csrf'] = csrf_missing_forms
        
        # Check for data leaks
        security_info['data_leaks_count'] = len(self.results["content"]["data_leaks"])
        
        # Store security information
        self.results["security_info"] = security_info
        
        # Print security findings
        print("\nSecurity Findings:")
        
        if is_https:
            print(f"  HTTPS: {Fore.GREEN}Enabled{Style.RESET_ALL}")
        else:
            print(f"  HTTPS: {Fore.RED}Disabled{Style.RESET_ALL}")
            
        if missing_headers:
            print(f"  Missing Security Headers: {Fore.YELLOW}{len(missing_headers)}{Style.RESET_ALL}")
            for header in missing_headers[:3]:  # Show first 3
                print(f"    - {header}")
            if len(missing_headers) > 3:
                print(f"    + {len(missing_headers) - 3} more")
                
        if 'mixed_content' in security_info and security_info['mixed_content']:
            print(f"  Mixed Content: {Fore.RED}Detected{Style.RESET_ALL}")
            
        if open_redirects:
            print(f"  Potential Open Redirects: {Fore.YELLOW}{len(open_redirects)}{Style.RESET_ALL}")
            
        if csrf_missing_forms:
            print(f"  Forms Without CSRF Protection: {Fore.YELLOW}{len(csrf_missing_forms)}{Style.RESET_ALL}")
            
        if security_info['data_leaks_count'] > 0:
            print(f"  Potential Data Leaks: {Fore.RED}{security_info['data_leaks_count']}{Style.RESET_ALL}")
    
    def _print_summary(self):
        """Print a summary of the scan results."""
        summary = [
            f"Target: {self.url}",
            f"Scan completed in: {self.results['metadata']['scan_duration']}",
            f"IP Address: {self.results['domain_info'].get('ip_address', 'Unknown')}",
            f"Pages Crawled: {len(self.visited_urls)}",
            f"Internal Links: {len(self.results['content']['links']['internal'])}",
            f"External Links: {len(self.results['content']['links']['external'])}",
            f"Resource Links: {len(self.results['content']['links']['resources'])}",
            f"Forms Detected: {len(self.results['content']['forms'])}",
            f"Emails Found: {len(self.results['contacts']['emails'])}",
            f"Phone Numbers Found: {len(self.results['contacts']['phones'])}",
        ]
        
        for line in summary:
            print(f"{Fore.WHITE}{line}{Style.RESET_ALL}")
            
        # Display found emails
        if self.results['contacts']['emails']:
            print(f"\n{Fore.CYAN}Discovered Emails:{Style.RESET_ALL}")
            for email in sorted(list(self.results['contacts']['emails']))[:10]:
                print(f"  {Fore.GREEN}{email}{Style.RESET_ALL}")
            if len(self.results['contacts']['emails']) > 10:
                print(f"  {Fore.GREEN}+ {len(self.results['contacts']['emails']) - 10} more{Style.RESET_ALL}")
        
        # Display found phone numbers
        if self.results['contacts']['phones']:
            print(f"\n{Fore.CYAN}Discovered Phone Numbers:{Style.RESET_ALL}")
            for phone in sorted(list(self.results['contacts']['phones']))[:5]:
                print(f"  {Fore.GREEN}{phone}{Style.RESET_ALL}")
            if len(self.results['contacts']['phones']) > 5:
                print(f"  {Fore.GREEN}+ {len(self.results['contacts']['phones']) - 5} more{Style.RESET_ALL}")
                
        # Display social media
        if self.results['contacts']['social_media']:
            print(f"\n{Fore.CYAN}Social Media Profiles:{Style.RESET_ALL}")
            for platform, profiles in self.results['contacts']['social_media'].items():
                if profiles:
                    profiles_list = sorted(list(profiles))
                    print(f"  {platform}: {Fore.GREEN}{profiles_list[0]}{Style.RESET_ALL}")
                    if len(profiles_list) > 1:
                        print(f"    {Fore.GREEN}+ {len(profiles_list) - 1} more{Style.RESET_ALL}")
    
    def _save_results(self):
        """Save results to a file."""
        try:
            # Prepare results for serialization
            serialized_results = self._prepare_return_results()
            
            # Determine file format
            if self.output.endswith('.json'):
                output_file = self.output
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(serialized_results, f, indent=2)
            else:
                # Default to JSON if no extension or unknown extension
                output_file = f"{self.output.rstrip('.')}.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(serialized_results, f, indent=2)
            
            print(f"\n{Fore.GREEN}Results saved to: {output_file}{Style.RESET_ALL}")
            
        except Exception as e:
            self._print_error(f"Failed to save results: {str(e)}")
    
    def _prepare_return_results(self) -> Dict:
        """
        Prepare results for return/serialization by converting sets to lists.
        
        Returns:
            Serializable results dictionary
        """
        serialized = {}
        
        # Helper function to convert sets to lists recursively
        def convert_sets(obj):
            if isinstance(obj, set):
                return sorted(list(obj))
            elif isinstance(obj, dict):
                return {k: convert_sets(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_sets(item) for item in obj]
            else:
                return obj
        
        # Convert the entire results structure
        serialized = convert_sets(self.results)
        
        return serialized

def main():
    """Main function to run the tool."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="WebForensicAnalyzer - Advanced Website Reconnaissance Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("url", help="Target URL to analyze")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Crawling depth (1-3)")
    parser.add_argument("-o", "--output", help="Output file path (JSON format)")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--shodan-api-key", help="Shodan API key for enhanced reconnaissance")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    
    args = parser.parse_args()
    
    try:
        # Create analyzer instance
        analyzer = WebForensicAnalyzer(
            url=args.url,
            depth=args.depth,
            timeout=args.timeout,
            output=args.output,
            verbose=args.verbose,
            delay=args.delay,
            user_agent=args.user_agent or DEFAULT_USER_AGENT,
            shodan_api_key=args.shodan_api_key,
            proxy=args.proxy
        )
        
        # Run analysis
        results = analyzer.analyze()
        
        # Exit with success
        return 0
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan interrupted by user{Style.RESET_ALL}")
        return 130
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    # Set DEBUG flag
    DEBUG = False
    
    # Run the tool and capture exit code
    exit_code = main()
    
    # Exit with appropriate code
    sys.exit(exit_code)