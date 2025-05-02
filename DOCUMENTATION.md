# WebForensicAnalyzer Documentation

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Command Line Interface](#command-line-interface)
4. [Core Functionality](#core-functionality)
5. [Output Format](#output-format)
6. [Practical Examples](#practical-examples)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)
9. [API Reference](#api-reference)
10. [Development](#development)

## Introduction

WebForensicAnalyzer is a comprehensive tool for website reconnaissance and forensic analysis. It's designed to help security professionals, researchers, and digital investigators gather detailed information about websites and web applications.

### Purpose

The tool addresses the need for a unified approach to web reconnaissance by combining multiple techniques:

- Domain information gathering
- Server technology detection
- Content discovery
- Contact information extraction
- Security assessment
- Data leak identification

### Architecture

WebForensicAnalyzer is built on a modular architecture, with key components including:

- Core analysis engine
- Multi-threaded crawler
- Data extraction modules
- Security analyzer
- Integration modules (Shodan, Nmap)

## Installation

### System Requirements

- Python 3.8 or higher
- 4GB RAM (recommended for deep crawls)
- Internet connection
- Optional: Nmap installation

### Standard Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/WebForensicAnalyzer.git
cd WebForensicAnalyzer

# Install required packages
pip install -r requirements.txt

# Make the script executable
chmod +x WebForensicAnalyzer.py
```

### Docker Installation

```bash
# Build the Docker image
docker build -t webforensicanalyzer .

# Run with Docker
docker run --rm webforensicanalyzer example.com
```

### Docker Compose Setup

1. Modify the `docker-compose.yml` file to set your target URL and options
2. Run:
   ```bash
   docker-compose up
   ```

## Command Line Interface

### Basic Syntax

```
WebForensicAnalyzer.py [URL] [OPTIONS]
```

### Options

| Option | Long Option | Description | Default |
|--------|-------------|-------------|---------|
| `-d` | `--depth` | Crawling depth (1-3) | 1 |
| `-o` | `--output` | Output file path (JSON format) | None |
| `-t` | `--timeout` | Request timeout in seconds | 10 |
| `-v` | `--verbose` | Enable verbose output | False |
| | `--delay` | Delay between requests in seconds | 0.5 |
| | `--user-agent` | Custom User-Agent string | Mozilla/5.0... |
| | `--shodan-api-key` | Shodan API key | None |
| | `--proxy` | Proxy URL | None |

### Examples

Basic scan:
```bash
./WebForensicAnalyzer.py example.com
```

Deep scan with output file:
```bash
./WebForensicAnalyzer.py example.com -d 3 -o results.json
```

Scan with custom settings:
```bash
./WebForensicAnalyzer.py example.com -v --delay 1.0 --proxy http://127.0.0.1:8080
```

## Core Functionality

### Domain Information Gathering

This module collects fundamental domain information:

- IP address resolution
- WHOIS data (registrar, creation date, expiration)
- DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)

### Server Information Analysis

Identifies server characteristics:

- Server type and version from HTTP headers
- Technology stack detection
- SSL/TLS certificate analysis
- Shodan intelligence (if configured)
- Port scanning (if Nmap is available)

### Web Crawling

The crawler module navigates through website pages:

- Respects crawl depth settings
- Multi-threaded processing
- Intelligent URL normalization
- Rate limiting to prevent overloading servers

### Content Analysis

Analyzes website content:

- Links (internal, external, resources)
- Forms and input fields
- Title and meta information
- Content type identification

### Contact Information Extraction

Identifies contact details:

- Email addresses
- Phone numbers
- Social media profiles

### Security Assessment

Evaluates security aspects:

- Security headers analysis
- HTTPS configuration
- Mixed content detection
- Open redirect vulnerability checking
- CSRF protection assessment

### Data Leak Detection

Searches for potentially sensitive information:

- API keys
- Authentication tokens
- Internal paths
- Database connection strings
- Private keys

## Output Format

### JSON Structure

```json
{
  "metadata": {
    "target": "https://example.com",
    "timestamp": "2023-04-01 12:34:56",
    "scan_duration": "45.32 seconds"
  },
  "domain_info": {
    "ip_address": "93.184.216.34",
    "whois": {
      "registrar": "Example Registrar, Inc.",
      "creation_date": "1995-08-14T00:00:00Z",
      "expiration_date": "2023-08-13T00:00:00Z",
      "name_servers": ["ns1.example.com", "ns2.example.com"]
    },
    "dns_records": {
      "A": ["93.184.216.34"],
      "MX": ["10 mail.example.com"],
      "NS": ["ns1.example.com", "ns2.example.com"]
    }
  },
  "server_info": {
    "Server": "Apache/2.4.41",
    "X-Powered-By": "PHP/7.4.3",
    "ssl_certificate": {
      "issuer": {"organizationName": "Let's Encrypt"},
      "notAfter": "2023-06-01T12:00:00Z"
    },
    "ports": {
      "80": {"state": "open", "service": "http"},
      "443": {"state": "open", "service": "https"}
    }
  },
  "technologies": {
    "web_server": "Apache/2.4.41",
    "framework": "PHP/7.4.3",
    "javascript_frameworks": ["jQuery", "Bootstrap"],
    "cms": ["WordPress"]
  },
  "contacts": {
    "emails": ["contact@example.com", "support@example.com"],
    "phones": ["+1-555-123-4567"],
    "social_media": {
      "Twitter": ["exampleofficial"],
      "LinkedIn": ["company/example"]
    }
  },
  "security_info": {
    "https": true,
    "missing_security_headers": ["Content-Security-Policy", "X-Frame-Options"],
    "mixed_content": false,
    "potential_open_redirects": [],
    "forms_without_csrf": ["https://example.com/contact"]
  },
  "content": {
    "pages": {
      "https://example.com/": {
        "title": "Example Domain",
        "status_code": 200,
        "content_type": "text/html; charset=UTF-8",
        "length": 1256
      }
    },
    "forms": [
      {
        "page_url": "https://example.com/contact",
        "action": "/submit",
        "method": "POST",
        "inputs": [
          {"type": "text", "name": "name", "required": true},
          {"type": "email", "name": "email", "required": true}
        ]
      }
    ],
    "links": {
      "internal": ["https://example.com/about", "https://example.com/contact"],
      "external": ["https://twitter.com/exampleofficial"],
      "resources": ["https://example.com/style.css", "https://example.com/logo.png"]
    },
    "data_leaks": [
      {
        "type": "API Key",
        "url": "https://example.com/js/main.js",
        "context": "apiKey = '[API_KEY_VALUE]';"
      }
    ]
  }
}
```

## Practical Examples

### Basic Reconnaissance

For a quick overview of a domain:

```bash
./WebForensicAnalyzer.py example.com
```

This provides essential information about the domain, server, and basic content structure.

### Security Assessment

For security evaluation:

```bash
./WebForensicAnalyzer.py example.com -d 2 -o security_report.json
```

This performs a more thorough analysis, with focus on security aspects and potential vulnerabilities.

### Content Discovery

For comprehensive content mapping:

```bash
./WebForensicAnalyzer.py example.com -d 3 --delay 1.0 -o content_map.json
```

This conducts a deep crawl, discovering as much content as possible while respecting server load with a 1-second delay.

### Anonymous Scanning

For privacy-focused reconnaissance:

```bash
./WebForensicAnalyzer.py example.com --proxy socks5://127.0.0.1:9050
```

This routes all requests through a proxy (in this example, a local Tor proxy).

## Advanced Usage

### Integration with Shodan

To leverage Shodan's extensive internet device database:

```bash
export SHODAN_API_KEY="your-api-key-here"
./WebForensicAnalyzer.py example.com
```

Or:

```bash
./WebForensicAnalyzer.py example.com --shodan-api-key "your-api-key-here"
```

### Custom User Agent

For specialized scanning needs:

```bash
./WebForensicAnalyzer.py example.com --user-agent "Mozilla/5.0 (compatible; CustomBot/1.0)"
```

### Output Processing

The JSON output can be further processed with tools like `jq`:

```bash
./WebForensicAnalyzer.py example.com -o - | jq '.security_info'
```

### Batch Processing

For scanning multiple targets:

```bash
cat targets.txt | while read target; do
  ./WebForensicAnalyzer.py "$target" -o "reports/${target//\//_}.json"
done
```

## Troubleshooting

### Common Issues

#### Connection Errors

**Problem**: Unable to connect to target website.
**Solution**: Check internet connection, verify the URL, or try increasing the timeout:
```bash
./WebForensicAnalyzer.py example.com -t 30
```

#### Rate Limiting

**Problem**: Target website is blocking requests due to rate limiting.
**Solution**: Increase the delay between requests:
```bash
./WebForensicAnalyzer.py example.com --delay 2.0
```

#### Missing Dependencies

**Problem**: Import errors when running the tool.
**Solution**: Verify all dependencies are installed:
```bash
pip install -r requirements.txt
```

### Debugging

For detailed execution information:

```bash
./WebForensicAnalyzer.py example.com -v
```

## API Reference

### Core Classes

#### WebForensicAnalyzer

The main class that orchestrates the analysis process.

```python
analyzer = WebForensicAnalyzer(
    url="example.com",
    depth=2,
    timeout=10,
    output="results.json",
    verbose=True,
    delay=0.5,
    user_agent="Custom User Agent",
    shodan_api_key="API_KEY",
    proxy="http://proxy:port"
)

results = analyzer.analyze()
```

### Key Methods

#### analyze()

Runs the complete analysis process.

#### _gather_domain_info()

Collects domain registration and DNS information.

#### _gather_server_info()

Gathers server information from HTTP headers.

#### _crawl_website()

Crawls the website to the specified depth.

#### _analyze_security()

Evaluates security aspects of the website.

## Development

### Project Structure

```
WebForensicAnalyzer/
├── WebForensicAnalyzer.py   # Main script
├── requirements.txt         # Python dependencies
├── Dockerfile               # Docker configuration
├── docker-compose.yml       # Docker Compose configuration
├── README.md                # Project overview
├── DOCUMENTATION.md         # Detailed documentation
├── LICENSE                  # License information
└── docs/                    # Additional documentation
```

### Adding New Features

To extend the tool with new capabilities:

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add appropriate tests
5. Submit a pull request

### Coding Standards

- Follow PEP 8 style guidelines
- Add docstrings for all classes and methods
- Include type hints for function parameters and return values
- Write unit tests for new functionality

---

This documentation is maintained by the WebForensicAnalyzer team. For questions or suggestions, please open an issue on the project repository.