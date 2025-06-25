# 🔍 Advanced Reconnaissance Suite

A comprehensive, professional-grade domain reconnaissance toolkit with three progressive levels of functionality, web interface, and containerization support.

## 📋 Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [Web Interface](#web-interface)
- [Docker Deployment](#docker-deployment)
- [API Documentation](#api-documentation)
- [Examples](#examples)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

## ✨ Features

### Level 1: Basic Reconnaissance
- 🌐 Subdomain enumeration via crt.sh API
- 🔍 DNS record lookup (A, NS, MX, TXT, CNAME)
- 📋 WHOIS information gathering
- 🌐 HTTP header analysis
- 🤖 robots.txt and sitemap.xml retrieval
- 🌍 GeoIP location detection

### Level 2: Intermediate Reconnaissance
- 🔓 Advanced port scanning with nmap
- 🏷️ Service banner grabbing
- 💻 Web technology stack detection
- 📧 Email address harvesting
- 🛰️ Shodan API integration
- 📊 Structured reporting (JSON/CSV)

### Level 3: Advanced Reconnaissance
- 📸 Automated screenshot capture
- 🛡️ WAF/CDN detection and analysis
- 🔒 Security header assessment
- 🔍 Basic vulnerability scanning
- 📄 Professional HTML report generation
- 🌐 Flask web interface
- 🐳 Docker containerization

## 🚀 Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip nmap nikto whois dnsutils chromium-browser

# CentOS/RHEL
sudo yum install python3 python3-pip nmap nikto whois bind-utils chromium

# macOS
brew install python3 nmap nikto whois
```

### Python Dependencies

```bash
# Clone the repository
git clone <repository-url>
cd advanced-recon-suite

# Install Python dependencies
pip3 install -r requirements.txt

# Or create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 📖 Usage

### Command Line Interface

#### Level 1: Basic Reconnaissance
```bash
# Basic usage
python3 basic_recon.py example.com

# With custom output file
python3 basic_recon.py example.com -o custom_report.txt

# Interactive mode (no arguments)
python3 basic_recon.py
```

#### Level 2: Intermediate Reconnaissance
```bash
# Run all modules
python3 intermediate_recon.py example.com

# Run specific modules
python3 intermediate_recon.py example.com -m basic portscan tech

# With Shodan API key
python3 intermediate_recon.py example.com --shodan-key YOUR_API_KEY

# Output in CSV format
python3 intermediate_recon.py example.com -f csv
```

#### Level 3: Advanced Reconnaissance
```bash
# Full advanced scan
python3 advanced_recon.py example.com

# Custom module selection
python3 advanced_recon.py example.com -m basic portscan screenshots waf report

# With Shodan integration
python3 advanced_recon.py example.com --shodan-key YOUR_API_KEY
```

### Web Interface

```bash
# Start the Flask web application
python3 app.py

# Access the web interface
# Open browser to: http://localhost:5000
```

## 🔧 Modules

| Module | Description | Level | CLI Flag |
|--------|-------------|-------|----------|
| **basic** | Subdomain enum, DNS, WHOIS, GeoIP | 1+ | `basic` |
| **portscan** | Nmap port scanning | 2+ | `portscan` |
| **banner** | Service banner grabbing | 2+ | `banner` |
| **tech** | Technology stack detection | 2+ | `tech` |
| **emails** | Email address harvesting | 2+ | `emails` |
| **shodan** | Shodan API integration | 2+ | `shodan` |
| **screenshots** | Automated screenshots | 3 | `screenshots` |
| **waf** | WAF/CDN detection | 3 | `waf` |
| **vulnscan** | Basic vulnerability scanning | 3 | `vulnscan` |
| **report** | HTML report generation | 3 | `report` |

## 🌐 Web Interface

The Flask web interface provides:

- 🎯 **Interactive Target Configuration**: Easy domain input and module selection
- 📊 **Real-time Progress Tracking**: Live scan progress and logging
- 📈 **Visual Results Dashboard**: Comprehensive results visualization
- 📥 **Report Downloads**: JSON and HTML report generation
- 📱 **Responsive Design**: Works on desktop and mobile devices

### Features:
- Real-time scan progress with live logs
- Module selection interface
- Results visualization
- Download links for reports
- Background processing
- Error handling and status tracking

## 🐳 Docker Deployment

### Quick Start with Docker

```bash
# Build the container
docker build -t advanced-recon-suite .

# Run the container
docker run -p 5000:5000 -v $(pwd)/reports:/app/reports advanced-recon-suite
```

### Docker Compose Deployment

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Docker Configuration

The Dockerfile includes:
- Ubuntu 22.04 base image
- All required system tools (nmap, nikto, etc.)
- Python environment with dependencies
- Non-root user for security
- Proper volume mounts for reports

## 📊 Report Formats

### JSON Report Structure
```json
{
  "domain": "example.com",
  "timestamp": "2024-01-15T10:30:00",
  "subdomains": ["www.example.com", "mail.example.com"],
  "dns_records": {
    "A": ["192.168.1.1"],
    "MX": ["mail.example.com"]
  },
  "port_scan": {
    "open_ports": [
      {"port": 80, "service": "http"},
      {"port": 443, "service": "https"}
    ]
  },
  "technology_stack": {
    "web_server": "nginx",
    "cms": "WordPress"
  }
}
```

### HTML Report Features
- 📊 Executive summary with key metrics
- 🔍 Detailed findings in collapsible sections
- 📸 Screenshot gallery
- 📈 Interactive charts and tables
- 🎨 Professional styling and branding
- 📱 Mobile-responsive design

## 🔑 API Keys and Configuration

### Shodan API
1. Register at [shodan.io](https://www.shodan.io/)
2. Get your API key from account settings
3. Use with `--shodan-key` parameter or web interface

### Configuration Files
```bash
# Create config directory
mkdir config

# Add API keys (optional)
echo "SHODAN_API_KEY=your_key_here" > config/.env
```

## 📝 Examples

### Example 1: Quick Basic Scan
```bash
python3 basic_recon.py google.com
```

### Example 2: Comprehensive Scan
```bash
python3 advanced_recon.py example.com -m basic portscan tech waf screenshots report
```

### Example 3: Automated Pipeline
```bash
#!/bin/bash
DOMAIN=$1
python3 advanced_recon.py $DOMAIN --shodan-key $SHODAN_KEY
echo "Reports available in reports/ directory"
```

## 📁 Directory Structure

```
advanced-recon-suite/
├── basic_recon.py          # Level 1 script
├── intermediate_recon.py   # Level 2 script
├── advanced_recon.py       # Level 3 script
├── app.py                  # Flask web interface
├── requirements.txt        # Python dependencies
├── Dockerfile             # Container configuration
├── docker-compose.yml     # Multi-container setup
├── README.md              # This file
├── templates/             # Flask templates
│   └── index.html
├── static/               # Static web assets
├── reports/              # Generated reports
│   ├── screenshots/      # Screenshot storage
│   └── vuln/            # Vulnerability reports
└── config/               # Configuration files
```

## 🔒 Security Considerations

### Ethical Usage
- ⚖️ Only scan domains you own or have explicit permission to test
- 📋 Comply with terms of service and local laws
- 🛡️ Use responsibly and ethically

### Security Features
- 🔐 Non-root Docker container execution
- 🚫 Input validation and sanitization
- 🔒 Secure API key handling
- 📊 Rate limiting considerations

## 🐛 Troubleshooting

### Common Issues

**Chrome/Selenium Issues:**
```bash
# Install Chrome dependencies
sudo apt-get install -y chromium-browser chromium-chromedriver

# Or use alternative browser
export CHROME_DRIVER_PATH=/usr/bin/chromedriver
```

**Permission Errors:**
```bash
# Fix file permissions
chmod +x *.py
sudo chown -R $USER:$USER reports/
```

**Network Issues:**
```bash
# Check firewall settings
sudo ufw allow 5000/tcp

# Test network connectivity
ping -c 4 8.8.8.8
```

## 📚 Dependencies

### Core Python Libraries
- `requests` - HTTP requests
- `dnspython` - DNS operations
- `python-whois` - WHOIS queries
- `python-nmap` - Port scanning
- `selenium` - Web automation
- `flask` - Web interface
- `jinja2` - Template rendering

### System Tools
- `nmap` - Network scanning
- `nikto` - Vulnerability scanning
- `whois` - Domain information
- `chromium` - Web screenshots

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations. The developers assume no liability for misuse of this software.

**Key Points:**
- 🔍 Only scan domains you own or have explicit written permission to test
- 📋 Comply with all applicable local, state, and federal laws
- 🛡️ Respect rate limits and terms of service of external APIs
- 📊 Use the information gathered responsibly and ethically

## 🙏 Acknowledgments

- Thanks to the open-source security community
- Special thanks to the developers of nmap, nikto, and other tools integrated
- Inspired by various reconnaissance frameworks and methodologies

---

**🔍 Happy Reconnaissance!** 

For support, issues, or feature requests, please open an issue on the project repository.
