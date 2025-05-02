# WebForensicAnalyzer

<div align="center">

![WebForensicAnalyzer Logo](https://via.placeholder.com/150)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://www.docker.com/)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)]()

**Advanced Web Reconnaissance & Forensic Analysis Tool**

</div>

## 🔍 Overview

WebForensicAnalyzer is a comprehensive, high-performance tool designed for advanced website reconnaissance and digital forensics. It automates the discovery and analysis of critical website information, security vulnerabilities, and digital artifacts that may be useful for security assessments, OSINT operations, and digital investigations.

### Key Features

- **Comprehensive Domain Analysis**: WHOIS data, DNS records, IP information
- **Server Intelligence**: Server type, technologies, SSL certificates, open ports
- **Content Discovery**: Crawls websites to discover links, resources, and content
- **Contact Extraction**: Emails, phone numbers, and social media profiles
- **Security Assessment**: Security headers, HTTPS configuration, open redirects, CSRF protection
- **Data Leak Detection**: Identifies potentially sensitive information
- **Integration Capabilities**: Shodan integration and Nmap for enhanced reconnaissance
- **Multi-threaded Architecture**: Fast, parallel processing for efficient scans

## 📋 Prerequisites

- Python 3.8 or higher
- Required Python packages (see [Installation](#-installation))
- Optional: Nmap for port scanning capabilities
- Optional: Shodan API key for enhanced reconnaissance

## 🚀 Installation

### Standard Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/WebForensicAnalyzer.git
   cd WebForensicAnalyzer
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Make the script executable:
   ```bash
   chmod +x WebForensicAnalyzer.py
   ```

### Docker Installation

1. Build the Docker image:
   ```bash
   docker build -t webforensicanalyzer .
   ```

2. Or use docker-compose:
   ```bash
   docker-compose build
   ```

## 💻 Usage

### Basic Usage

```bash
./WebForensicAnalyzer.py example.com
```

### Advanced Options

```bash
./WebForensicAnalyzer.py example.com -d 2 -o results.json -v --delay 1
```

### With Docker

```bash
docker run --rm webforensicanalyzer example.com -d 2 -o /app/results.json
```

```bash
# Modify docker-compose.yml target then run:
docker-compose up
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `url` | Target URL to analyze | (Required) |
| `-d`, `--depth` | Crawling depth (1-3) | 1 |
| `-o`, `--output` | Output file path (JSON format) | None |
| `-t`, `--timeout` | Request timeout in seconds | 10 |
| `-v`, `--verbose` | Enable verbose output | False |
| `--delay` | Delay between requests in seconds | 0.5 |
| `--user-agent` | Custom User-Agent string | Mozilla/5.0... |
| `--shodan-api-key` | Shodan API key for enhanced reconnaissance | None |
| `--proxy` | Proxy URL (e.g., http://127.0.0.1:8080) | None |

## 📊 Output

The tool generates detailed JSON output containing:

- Domain information (WHOIS, DNS records)
- Server information (headers, technologies)
- Security findings (headers, configuration)
- Content analysis (links, forms, resources)
- Contact information (emails, phones, social media)
- Potential data leaks

Example output structure:
```json
{
  "metadata": {
    "target": "https://example.com",
    "timestamp": "2023-04-01 12:34:56",
    "scan_duration": "45.32 seconds"
  },
  "domain_info": { ... },
  "server_info": { ... },
  "technologies": { ... },
  "security_info": { ... },
  "content": { ... },
  "contacts": { ... }
}
```

## 🔧 Advanced Configuration

### Environment Variables

The tool respects the following environment variables:

- `WFA_USER_AGENT`: Default User-Agent to use
- `WFA_TIMEOUT`: Default timeout for requests
- `SHODAN_API_KEY`: API key for Shodan integration

### Configuration File (Optional)

You can create a `config.json` file in the same directory as the script with the following structure:

```json
{
  "default_user_agent": "Custom User Agent",
  "default_timeout": 15,
  "default_delay": 1.0,
  "shodan_api_key": "your-api-key-here"
}
```

## 🛡️ Security and Privacy

- All connections can be proxied for anonymity
- Rate limiting to prevent overloading target servers
- No data is sent to third parties except when using Shodan integration

## 🔄 Integrations

### Shodan

To enable Shodan intelligence gathering:

1. Get a Shodan API key from [shodan.io](https://shodan.io)
2. Use the `--shodan-api-key` parameter or set the `SHODAN_API_KEY` environment variable

### Nmap

Ensure Nmap is installed on your system for port scanning capabilities:

- Ubuntu/Debian: `apt-get install nmap`
- CentOS/RHEL: `yum install nmap`
- macOS: `brew install nmap`
- Windows: Download from [nmap.org](https://nmap.org/download.html)

## 🌟 Use Cases

- Security professionals performing reconnaissance
- Digital forensics investigations
- Website administrators auditing their sites
- OSINT (Open Source Intelligence) gathering
- Security researchers analyzing web applications

## 📘 Documentation

For more detailed documentation, see [DOCUMENTATION.md](docs/DOCUMENTATION.md).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- [Requests](https://requests.readthedocs.io/) - Elegant HTTP library
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing library
- [Shodan](https://www.shodan.io/) - Search engine for Internet-connected devices
- [python-nmap](https://pypi.org/project/python-nmap/) - Nmap port scanner interface

## 🔗 Contact

Project Link: [https://github.com/yourusername/WebForensicAnalyzer](https://github.com/yourusername/WebForensicAnalyzer)

---



