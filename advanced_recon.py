#!/usr/bin/env python3
"""
Advanced Reconnaissance Suite
Level 3: Professional-grade toolkit with screenshots, WAF detection, and reporting
"""

import sys
import os
import argparse
import json
import subprocess
import time
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from intermediate_recon import IntermediateRecon
import requests
from jinja2 import Template
import threading

class AdvancedRecon(IntermediateRecon):
    def __init__(self, domain):
        super().__init__(domain)
        self.results.update({
            'screenshots': {},
            'waf_detection': {},
            'vulnerability_scan': {},
            'security_headers': {}
        })
        
        # Ensure directories exist
        os.makedirs('reports', exist_ok=True)
        os.makedirs('reports/screenshots', exist_ok=True)
        os.makedirs('reports/vuln', exist_ok=True)
    
    def capture_screenshots(self):
        """Capture screenshots of discovered subdomains"""
        print(f"[+] Capturing screenshots of subdomains...")
        
        # Configure Chrome options for headless mode
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--window-size=1920,1080')
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Get list of domains to screenshot (main domain + subdomains)
        domains_to_screenshot = [self.domain]
        if self.results.get('subdomains'):
            # Limit to first 10 subdomains to avoid taking too long
            domains_to_screenshot.extend(self.results['subdomains'][:10])
        
        for domain in domains_to_screenshot:
            protocols = ['https', 'http']
            for protocol in protocols:
                try:
                    print(f"[+] Capturing screenshot for {protocol}://{domain}")
                    
                    driver = webdriver.Chrome(options=chrome_options)
                    driver.set_page_load_timeout(30)
                    
                    url = f"{protocol}://{domain}"
                    driver.get(url)
                    
                    # Wait for page to load
                    time.sleep(3)
                    
                    # Take screenshot
                    screenshot_filename = f"{domain}_{protocol}_{timestamp}.png"
                    screenshot_path = os.path.join('reports', 'screenshots', screenshot_filename)
                    driver.save_screenshot(screenshot_path)
                    
                    self.results['screenshots'][f"{protocol}://{domain}"] = {
                        'filename': screenshot_filename,
                        'path': screenshot_path,
                        'timestamp': timestamp,
                        'status': 'success'
                    }
                    
                    driver.quit()
                    print(f"[+] Screenshot saved: {screenshot_filename}")
                    break  # If https works, don't try http
                    
                except Exception as e:
                    if 'driver' in locals():
                        driver.quit()
                    print(f"[-] Error capturing screenshot for {protocol}://{domain}: {e}")
                    self.results['screenshots'][f"{protocol}://{domain}"] = {
                        'status': 'failed',
                        'error': str(e)
                    }
    
    def detect_waf_cdn(self):
        """Detect Web Application Firewalls and CDN services"""
        print(f"[+] Detecting WAF/CDN for {self.domain}...")
        
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'AWS CloudFront': ['cloudfront', 'x-amz-cf-id'],
            'Akamai': ['akamai', 'x-akamai'],
            'Incapsula': ['incap_ses', 'visid_incap'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'F5 BIG-IP': ['f5-bigip', 'x-waf-event'],
            'Fastly': ['fastly', 'x-served-by'],
            'KeyCDN': ['keycdn', 'x-edge-location']
        }
        
        detected_waf = []
        detected_cdn = []
        
        try:
            # Check main domain
            response = requests.get(f"https://{self.domain}", timeout=10)
            headers = response.headers
            content = response.text.lower()
            
            # Check headers and content for signatures
            for waf_name, signatures in waf_signatures.items():
                found = False
                for signature in signatures:
                    if any(signature in str(value).lower() for value in headers.values()) or \
                       signature in content:
                        found = True
                        break
                
                if found:
                    if 'cdn' in waf_name.lower() or waf_name in ['Cloudflare', 'AWS CloudFront', 'Akamai', 'Fastly', 'KeyCDN']:
                        detected_cdn.append(waf_name)
                    else:
                        detected_waf.append(waf_name)
            
            # Additional WAF detection through error pages
            try:
                # Try to trigger WAF with malicious payload
                test_url = f"https://{self.domain}/?test=<script>alert(1)</script>"
                test_response = requests.get(test_url, timeout=10)
                
                waf_keywords = ['blocked', 'forbidden', 'access denied', 'security', 'firewall']
                if any(keyword in test_response.text.lower() for keyword in waf_keywords):
                    if not detected_waf:
                        detected_waf.append('Unknown WAF')
            except:
                pass
            
            self.results['waf_detection'] = {
                'waf_detected': detected_waf,
                'cdn_detected': detected_cdn,
                'security_headers': self.check_security_headers(headers)
            }
            
            print(f"[+] WAF Detection: {', '.join(detected_waf) if detected_waf else 'None detected'}")
            print(f"[+] CDN Detection: {', '.join(detected_cdn) if detected_cdn else 'None detected'}")
            
        except Exception as e:
            print(f"[-] Error in WAF/CDN detection: {e}")
    
    def check_security_headers(self, headers):
        """Check for important security headers"""
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Missing')
        }
        return security_headers
    
    def vulnerability_scan_basic(self):
        """Perform basic vulnerability scanning using Nikto"""
        print(f"[+] Performing basic vulnerability scan...")
        
        try:
            # Run Nikto scan
            nikto_cmd = ['nikto', '-h', f"https://{self.domain}", '-Format', 'txt']
            result = subprocess.run(nikto_cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Save Nikto results
                nikto_output = result.stdout
                vuln_file = os.path.join('reports', 'vuln', f'{self.domain}_nikto.txt')
                with open(vuln_file, 'w') as f:
                    f.write(nikto_output)
                
                # Parse critical findings
                critical_findings = []
                for line in nikto_output.split('\n'):
                    if any(keyword in line.lower() for keyword in ['critical', 'high', 'vulnerability', 'exploit']):
                        critical_findings.append(line.strip())
                
                self.results['vulnerability_scan'] = {
                    'tool': 'Nikto',
                    'scan_file': vuln_file,
                    'critical_findings': critical_findings[:10],  # Limit to 10
                    'total_findings': len(nikto_output.split('\n'))
                }
                
                print(f"[+] Vulnerability scan completed, {len(critical_findings)} critical findings")
                
            else:
                print(f"[-] Nikto scan failed: {result.stderr}")
                
        except FileNotFoundError:
            print(f"[-] Nikto not found, skipping vulnerability scan")
        except Exception as e:
            print(f"[-] Error in vulnerability scan: {e}")
    
    def generate_html_report(self):
        """Generate comprehensive HTML report"""
        print(f"[+] Generating HTML report...")
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Reconnaissance Report - {{ domain }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; border-bottom: 3px solid #007acc; padding-bottom: 20px; }
        .section { margin: 30px 0; }
        .section h2 { color: #007acc; border-left: 4px solid #007acc; padding-left: 15px; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .info-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #28a745; }
        .warning-card { border-left-color: #ffc107; }
        .danger-card { border-left-color: #dc3545; }
        .list-item { padding: 8px 0; border-bottom: 1px solid #eee; }
        .screenshot { max-width: 300px; margin: 10px; border: 1px solid #ddd; border-radius: 4px; }
        .collapsible { background-color: #007acc; color: white; cursor: pointer; padding: 15px; border: none; text-align: left; outline: none; font-size: 16px; border-radius: 4px; margin: 5px 0; width: 100%; }
        .collapsible:hover { background-color: #005fa3; }
        .content { padding: 0 15px; display: none; overflow: hidden; background-color: #f8f9fa; border-radius: 0 0 4px 4px; }
        .badge { display: inline-block; padding: 3px 8px; background: #007acc; color: white; border-radius: 12px; font-size: 12px; margin: 2px; }
        .badge.success { background: #28a745; }
        .badge.warning { background: #ffc107; color: black; }
        .badge.danger { background: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #007acc; color: white; }
        tr:hover { background-color: #f5f5f5; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Advanced Reconnaissance Report</h1>
            <h2>{{ domain }}</h2>
            <p>Generated on: {{ timestamp }}</p>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>🌐 Subdomains Found</h3>
                    <p><strong>{{ subdomains|length }}</strong> subdomains discovered</p>
                </div>
                <div class="info-card {{ 'warning-card' if open_ports else '' }}">
                    <h3>🔓 Open Ports</h3>
                    <p><strong>{{ open_ports|length }}</strong> open ports detected</p>
                </div>
                <div class="info-card {{ 'danger-card' if waf_detected else 'success-card' }}">
                    <h3>🛡️ Security</h3>
                    <p>WAF: {{ waf_detected|join(', ') if waf_detected else 'Not detected' }}</p>
                </div>
                <div class="info-card">
                    <h3>📧 Intelligence</h3>
                    <p><strong>{{ emails|length }}</strong> email addresses found</p>
                </div>
            </div>
        </div>

        <!-- Subdomains -->
        <div class="section">
            <button class="collapsible">🌐 Subdomains ({{ subdomains|length }})</button>
            <div class="content">
                <table>
                    <tr><th>Subdomain</th><th>Status</th></tr>
                    {% for subdomain in subdomains[:50] %}
                    <tr><td>{{ subdomain }}</td><td><span class="badge success">Discovered</span></td></tr>
                    {% endfor %}
                </table>
            </div>
        </div>

        <!-- Port Scan Results -->
        {% if open_ports %}
        <div class="section">
            <button class="collapsible">🔓 Port Scan Results</button>
            <div class="content">
                <table>
                    <tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>
                    {% for port in open_ports %}
                    <tr>
                        <td>{{ port.port }}</td>
                        <td>{{ port.service }}</td>
                        <td>{{ port.product or 'Unknown' }}</td>
                        <td>{{ port.version or 'Unknown' }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
        </div>
        {% endif %}

        <!-- Technology Stack -->
        {% if technology_stack %}
        <div class="section">
            <button class="collapsible">💻 Technology Stack</button>
            <div class="content">
                <div class="info-grid">
                    <div class="info-card">
                        <h3>Web Server</h3>
                        <p>{{ technology_stack.web_server }}</p>
                    </div>
                    <div class="info-card">
                        <h3>CMS</h3>
                        <p>{{ technology_stack.cms }}</p>
                    </div>
                    <div class="info-card">
                        <h3>Programming Languages</h3>
                        {% for lang in technology_stack.programming_language %}
                        <span class="badge">{{ lang }}</span>
                        {% endfor %}
                    </div>
                    <div class="info-card">
                        <h3>Frameworks</h3>
                        {% for framework in technology_stack.frameworks %}
                        <span class="badge">{{ framework }}</span>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </div>
        {% endif %}

        <!-- Security Analysis -->
        <div class="section">
            <button class="collapsible">🛡️ Security Analysis</button>
            <div class="content">
                {% if waf_detected %}
                <h3>🔥 WAF Detection</h3>
                {% for waf in waf_detected %}
                <span class="badge warning">{{ waf }}</span>
                {% endfor %}
                {% endif %}

                {% if cdn_detected %}
                <h3>☁️ CDN Detection</h3>
                {% for cdn in cdn_detected %}
                <span class="badge">{{ cdn }}</span>
                {% endfor %}
                {% endif %}

                {% if security_headers %}
                <h3>🔒 Security Headers</h3>
                <table>
                    <tr><th>Header</th><th>Status</th></tr>
                    {% for header, value in security_headers.items() %}
                    <tr>
                        <td>{{ header }}</td>
                        <td><span class="badge {{ 'danger' if value == 'Missing' else 'success' }}">{{ value }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
                {% endif %}
            </div>
        </div>

        <!-- Screenshots -->
        {% if screenshots %}
        <div class="section">
            <button class="collapsible">📸 Screenshots</button>
            <div class="content">
                <div style="display: flex; flex-wrap: wrap;">
                {% for url, screenshot in screenshots.items() %}
                    {% if screenshot.status == 'success' %}
                    <div style="margin: 10px;">
                        <h4>{{ url }}</h4>
                        <img src="screenshots/{{ screenshot.filename }}" alt="{{ url }}" class="screenshot">
                    </div>
                    {% endif %}
                {% endfor %}
                </div>
            </div>
        </div>
        {% endif %}

        <!-- Intelligence -->
        {% if emails %}
        <div class="section">
            <button class="collapsible">📧 Email Intelligence</button>
            <div class="content">
                <table>
                    <tr><th>Email Address</th><th>Source</th></tr>
                    {% for email in emails %}
                    <tr><td>{{ email }}</td><td><span class="badge">Web Scraping</span></td></tr>
                    {% endfor %}
                </table>
            </div>
        </div>
        {% endif %}

        <!-- DNS Records -->
        {% if dns_records %}
        <div class="section">
            <button class="collapsible">🌍 DNS Records</button>
            <div class="content">
                {% for record_type, records in dns_records.items() %}
                    {% if records %}
                    <h3>{{ record_type }} Records</h3>
                    <ul>
                    {% for record in records %}
                        <li class="list-item">{{ record }}</li>
                    {% endfor %}
                    </ul>
                    {% endif %}
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <div class="section" style="text-align: center; margin-top: 50px; color: #666;">
            <p>Report generated by Advanced Reconnaissance Suite</p>
            <p>⚠️ This report is for authorized security testing only</p>
        </div>
    </div>

    <script>
        var coll = document.getElementsByClassName("collapsible");
        for (var i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.display === "block") {
                    content.style.display = "none";
                } else {
                    content.style.display = "block";
                }
            });
        }
    </script>
</body>
</html>
        """
        
        try:
            template = Template(html_template)
            
            # Prepare data for template
            template_data = {
                'domain': self.domain,
                'timestamp': self.results['timestamp'],
                'subdomains': self.results.get('subdomains', []),
                'open_ports': self.results.get('port_scan', {}).get('open_ports', []),
                'technology_stack': self.results.get('technology_stack', {}),
                'waf_detected': self.results.get('waf_detection', {}).get('waf_detected', []),
                'cdn_detected': self.results.get('waf_detection', {}).get('cdn_detected', []),
                'security_headers': self.results.get('waf_detection', {}).get('security_headers', {}),
                'screenshots': self.results.get('screenshots', {}),
                'emails': self.results.get('emails', []),
                'dns_records': self.results.get('dns_records', {})
            }
            
            # Generate HTML
            html_content = template.render(**template_data)
            
            # Save HTML report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            html_filename = f"{self.domain}_advanced_report_{timestamp}.html"
            html_path = os.path.join('reports', html_filename)
            
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"[+] HTML report generated: {html_path}")
            
        except Exception as e:
            print(f"[-] Error generating HTML report: {e}")
    
    def run_advanced_recon(self, modules=None, shodan_key=None):
        """Run advanced reconnaissance with all modules"""
        available_modules = {
            'basic': self.run_recon,
            'portscan': lambda: self.port_scan_nmap(),
            'banner': self.banner_grabbing,
            'tech': self.detect_technology,
            'emails': self.harvest_emails,
            'shodan': lambda: self.shodan_lookup(shodan_key),
            'screenshots': self.capture_screenshots,
            'waf': self.detect_waf_cdn,
            'vulnscan': self.vulnerability_scan_basic,
            'report': self.generate_html_report
        }
        
        if modules is None:
            modules = list(available_modules.keys())
        
        print(f"\n{'='*60}")
        print(f"Starting Advanced Reconnaissance for: {self.domain}")
        print(f"Modules: {', '.join(modules)}")
        print(f"{'='*60}")
        
        for module in modules:
            if module in available_modules:
                try:
                    available_modules[module]()
                except Exception as e:
                    print(f"[-] Error in {module} module: {e}")
            else:
                print(f"[-] Unknown module: {module}")
        
        print(f"\n{'='*60}")
        print("Advanced reconnaissance completed!")
        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description='Advanced Domain Reconnaissance Suite')
    parser.add_argument('domain', nargs='?', help='Target domain to scan')
    parser.add_argument('-m', '--modules', nargs='+', 
                       choices=['basic', 'portscan', 'banner', 'tech', 'emails', 'shodan', 
                               'screenshots', 'waf', 'vulnscan', 'report'],
                       help='Modules to run (default: all)')
    parser.add_argument('--shodan-key', help='Shodan API key')
    
    args = parser.parse_args()
    
    # Get domain from argument or prompt
    if args.domain:
        domain = args.domain
    else:
        domain = input("Enter target domain: ").strip()
    
    if not domain:
        print("[-] No domain provided")
        sys.exit(1)
    
    # Remove protocol if present
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    # Initialize and run reconnaissance
    recon = AdvancedRecon(domain)
    recon.run_advanced_recon(modules=args.modules, shodan_key=args.shodan_key)
    recon.display_intermediate_results()


if __name__ == "__main__":
    main()
