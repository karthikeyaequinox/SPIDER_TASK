#!/usr/bin/env python3
"""
Intermediate Reconnaissance 
"""

import sys
import argparse
import json
import csv
import os
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from basic_recon import BasicRecon

import requests
from bs4 import BeautifulSoup
import re

class IntermediateRecon(BasicRecon):
    def __init__(self, domain):
        super().__init__(domain)
        self.results.update({
            'port_scan': {},
            'banner_grab': {},
            'technology_stack': {},
            'emails': [],
            'shodan_info': {}
        })
        # Check if nmap is available
        self.nmap_available = self.check_nmap_availability()
    
    def check_nmap_availability(self):
        """Check if nmap is available on the system"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def port_scan_nmap(self, ports="1-1000", scan_type="-sS"):
        """Perform simple port scanning using CLI nmap - only open ports and states"""
        if not self.nmap_available:
            print(f"[-] Nmap not available, skipping port scan")
            print(f"[-] Install nmap: sudo apt-get install nmap")
            self.results['port_scan'] = {
                'error': 'Nmap not available',
                'open_ports': []
            }
            return
            
        print(f"[+] Scanning ports {ports} on {self.domain}...")
        try:
            # Get target IP
            target_ip = socket.gethostbyname(self.domain)
            print(f"[+] Target IP: {target_ip}")
            
            # Prepare simple nmap command - only basic port scanning
            xml_output = f"/tmp/nmap_scan_{self.domain}_{int(time.time())}.xml"
            nmap_cmd = [
                'nmap',
                scan_type,          # SYN scan
                '-p', ports,        # Port range
                '-oX', xml_output,  # XML output
                target_ip
            ]
            
            print(f"[+] Running: {' '.join(nmap_cmd)}")
            
            # Execute nmap scan
            result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                # Parse XML output
                self.parse_simple_nmap_xml(xml_output, target_ip, scan_type, ports)
                
                # Clean up temp file
                if os.path.exists(xml_output):
                    os.remove(xml_output)
                    
                print(f"[+] Found {len(self.results['port_scan']['open_ports'])} open ports")
            else:
                print(f"[-] Nmap scan failed: {result.stderr}")
                # Fall back to basic scan
                self.basic_port_scan(target_ip, ports)
                
        except subprocess.TimeoutExpired:
            print(f"[-] Nmap scan timed out")
        except Exception as e:
            print(f"[-] Error during port scan: {e}")
    
    def parse_simple_nmap_xml(self, xml_file, target_ip, scan_type, ports):
        """Parse nmap XML output - simplified version for ports and states only"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            self.results['port_scan'] = {
                'target_ip': target_ip,
                'scan_type': scan_type,
                'ports_scanned': ports,
                'open_ports': [],
                'host_status': 'unknown'
            }
            
            # Find host information
            host = root.find('host')
            if host is not None:
                # Get host status
                status = host.find('status')
                if status is not None:
                    self.results['port_scan']['host_status'] = status.get('state', 'unknown')
                
                # Get port information - simplified
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        
                        state = port.find('state')
                        if state is not None:
                            port_state = state.get('state')
                            
                            # Only store open ports
                            if port_state == 'open':
                                port_data = {
                                    'port': int(port_id),
                                    'protocol': protocol,
                                    'state': port_state
                                }
                                self.results['port_scan']['open_ports'].append(port_data)
                        
        except Exception as e:
            print(f"[-] Error parsing nmap XML: {e}")
    
    def basic_port_scan(self, target_ip, port_range):
        """Basic port scan fallback using socket connections"""
        print(f"[+] Performing basic port scan fallback...")
        
        self.results['port_scan'] = {
            'target_ip': target_ip,
            'scan_type': 'basic_tcp',
            'ports_scanned': port_range,
            'open_ports': [],
            'host_status': 'up'
        }
        
        # Parse port range
        if '-' in port_range:
            start_port, end_port = map(int, port_range.split('-'))
            ports_to_scan = range(start_port, min(end_port + 1, 1001))  # Limit to 1000 ports max
        else:
            ports_to_scan = [int(port_range)]
        
        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    port_data = {
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open'
                    }
                    self.results['port_scan']['open_ports'].append(port_data)
                
                sock.close()
                
            except Exception:
                continue
    
    def banner_grabbing(self):
        """Perform banner grabbing on open ports"""
        print(f"[+] Performing banner grabbing...")
        
        if not self.results['port_scan'].get('open_ports'):
            print(f"[-] No open ports found for banner grabbing")
            return
        
        target_ip = self.results['port_scan']['target_ip']
        
        # Common service names for banner grabbing
        common_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 993: 'imaps', 995: 'pop3s'
        }
        
        for port_info in self.results['port_scan']['open_ports']:
            port = port_info['port']
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target_ip, port))
                
                # Send appropriate request based on common ports
                if port in [80, 8080]:
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: " + self.domain.encode() + b"\r\n\r\n")
                elif port == 443:
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: " + self.domain.encode() + b"\r\n\r\n")
                elif port == 21:
                    pass  # FTP sends banner automatically
                elif port == 25:
                    sock.send(b"EHLO test.com\r\n")
                elif port == 110:
                    pass  # POP3 sends banner automatically
                else:
                    sock.send(b"\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                
                if banner:
                    self.results['banner_grab'][port] = {
                        'service': common_services.get(port, 'unknown'),
                        'banner': banner
                    }
                    print(f"[+] Banner grabbed for port {port}")
                
            except Exception as e:
                print(f"[-] Error grabbing banner for port {port}: {e}")
    
    def detect_technology(self):
        """Detect web technologies using HTTP headers and content analysis"""
        print(f"[+] Detecting web technologies...")
        
        tech_stack = {
            'web_server': 'Unknown',
            'programming_language': [],
            'frameworks': [],
            'cms': 'Unknown',
            'javascript_libraries': [],
            'cdn': 'Unknown'
        }
        
        try:
            # Analyze HTTP headers
            for protocol in ['http', 'https']:
                if protocol in self.results['http_headers']:
                    headers = self.results['http_headers'][protocol]
                    
                    # Web server detection
                    if 'Server' in headers:
                        tech_stack['web_server'] = headers['Server']
                    
                    # Framework detection from headers
                    for header, value in headers.items():
                        if 'php' in value.lower():
                            tech_stack['programming_language'].append('PHP')
                        if 'asp.net' in value.lower():
                            tech_stack['programming_language'].append('ASP.NET')
                        if 'express' in value.lower():
                            tech_stack['frameworks'].append('Express.js')
                        if 'cloudflare' in value.lower():
                            tech_stack['cdn'] = 'Cloudflare'
            
            # Analyze page content
            try:
                response = requests.get(f"https://{self.domain}", timeout=10)
                content = response.text.lower()
                
                # CMS detection
                if 'wp-content' in content or 'wordpress' in content:
                    tech_stack['cms'] = 'WordPress'
                elif 'drupal' in content:
                    tech_stack['cms'] = 'Drupal'
                elif 'joomla' in content:
                    tech_stack['cms'] = 'Joomla'
                
                # JavaScript library detection
                js_libraries = ['jquery', 'react', 'angular', 'vue', 'bootstrap']
                for lib in js_libraries:
                    if lib in content:
                        tech_stack['javascript_libraries'].append(lib.capitalize())
                
            except Exception as e:
                print(f"[-] Error analyzing page content: {e}")
            
            self.results['technology_stack'] = tech_stack
            print(f"[+] Technology detection completed")
            
        except Exception as e:
            print(f"[-] Error in technology detection: {e}")
    
    def harvest_emails(self):
        """Harvest emails using web scraping"""
        print(f"[+] Harvesting emails for {self.domain}...")
        
        emails = set()
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
        try:
            # Search main domain
            urls_to_check = [
                f"https://{self.domain}",
                f"https://{self.domain}/contact",
                f"https://{self.domain}/about",
                f"https://{self.domain}/team"
            ]
            
            for url in urls_to_check:
                try:
                    response = requests.get(url, timeout=10)
                    found_emails = email_pattern.findall(response.text)
                    for email in found_emails:
                        if self.domain in email:  # Only emails from target domain
                            emails.add(email)
                except:
                    continue
            
            # Check robots.txt for additional emails
            if self.results.get('robots_txt'):
                found_emails = email_pattern.findall(self.results['robots_txt'])
                emails.update(found_emails)
            
            self.results['emails'] = list(emails)
            print(f"[+] Found {len(emails)} email addresses")
            
        except Exception as e:
            print(f"[-] Error harvesting emails: {e}")
    
    def shodan_lookup(self, api_key=None):
        """Query Shodan API for detailed service information"""
        print(f"[+] Performing Shodan lookup...")
        
        if not api_key:
            print(f"[-] No Shodan API key provided, skipping Shodan lookup")
            return
        
        try:
            try:
                import shodan
                SHODAN_AVAILABLE = True
            except ImportError:
                print(f"[-] Shodan library not installed, skipping Shodan lookup")
                print(f"[-] Install with: pip install shodan")
                return
            
            api = shodan.Shodan(api_key)
            target_ip = socket.gethostbyname(self.domain)
            
            # Search for the IP
            host = api.host(target_ip)
            
            self.results['shodan_info'] = {
                'ip': target_ip,
                'organization': host.get('org', 'Unknown'),
                'operating_system': host.get('os', 'Unknown'),
                'ports': host.get('ports', []),
                'vulnerabilities': host.get('vulns', []),
                'tags': host.get('tags', []),
                'hostnames': host.get('hostnames', [])
            }
            
            print(f"[+] Shodan lookup completed")
            
        except ImportError:
            print(f"[-] Shodan library not installed")
        except Exception as e:
            print(f"[-] Error in Shodan lookup: {e}")
    
    def run_intermediate_recon(self, modules=None, shodan_key=None):
        """Run selected reconnaissance modules"""
        available_modules = {
            'basic': self.run_recon,
            'portscan': lambda: self.port_scan_nmap(),
            'banner': self.banner_grabbing,
            'tech': self.detect_technology,
            'emails': self.harvest_emails,
            'shodan': lambda: self.shodan_lookup(shodan_key)
        }
        
        if modules is None:
            modules = list(available_modules.keys())
        
        print(f"\n{'='*60}")
        print(f"Starting Intermediate Reconnaissance for: {self.domain}")
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
        print("Intermediate reconnaissance completed!")
        print(f"{'='*60}")
    
    def save_structured_report(self, format_type='json', filename=None):
        """Save structured report in JSON or CSV format"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.domain}_report_{timestamp}.{format_type}"
        
        # Ensure reports directory exists
        os.makedirs('reports', exist_ok=True)
        filepath = os.path.join('reports', filename)
        
        try:
            if format_type.lower() == 'json':
                with open(filepath, 'w') as f:
                    json.dump(self.results, f, indent=2, default=str)
                print(f"[+] JSON report saved to: {filepath}")
                
            elif format_type.lower() == 'csv':
                # Create CSV with flattened data
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f)
                    
                    # Write header
                    writer.writerow(['Category', 'Type', 'Value', 'Details'])
                    
                    # Write subdomains
                    for subdomain in self.results.get('subdomains', []):
                        writer.writerow(['Subdomains', 'Subdomain', subdomain, ''])
                    
                    # Write DNS records
                    for record_type, records in self.results.get('dns_records', {}).items():
                        for record in records:
                            writer.writerow(['DNS', record_type, record, ''])
                    
                    # Write open ports - simplified
                    for port_info in self.results.get('port_scan', {}).get('open_ports', []):
                        writer.writerow(['Ports', 'Open Port', port_info['port'], 
                                       f"State: {port_info['state']}"])
                    
                    # Write emails
                    for email in self.results.get('emails', []):
                        writer.writerow(['Intelligence', 'Email', email, ''])
                    
                    # Write technology stack
                    tech = self.results.get('technology_stack', {})
                    for tech_type, tech_value in tech.items():
                        if isinstance(tech_value, list):
                            for item in tech_value:
                                writer.writerow(['Technology', tech_type, item, ''])
                        else:
                            writer.writerow(['Technology', tech_type, tech_value, ''])
                
                print(f"[+] CSV report saved to: {filepath}")
            
        except Exception as e:
            print(f"[-] Error saving structured report: {e}")
    
    def display_intermediate_results(self):
        """Display intermediate reconnaissance results"""
        super().display_results()
        
        # Port scan results - simplified
        if self.results.get('port_scan', {}).get('open_ports'):
            print(f"\n[PORT SCAN RESULTS]:")
            for port_info in self.results['port_scan']['open_ports']:
                print(f"  • Port {port_info['port']}: {port_info['state']}")
        
        # Banner grab results
        if self.results.get('banner_grab'):
            print(f"\n[BANNER GRAB RESULTS]:")
            for port, banner_info in self.results['banner_grab'].items():
                print(f"  • Port {port} ({banner_info['service']}): {banner_info['banner'][:50]}...")
        
        # Technology stack
        if self.results.get('technology_stack'):
            tech = self.results['technology_stack']
            print(f"\n[TECHNOLOGY STACK]:")
            print(f"  • Web Server: {tech.get('web_server', 'Unknown')}")
            print(f"  • CMS: {tech.get('cms', 'Unknown')}")
            if tech.get('programming_language'):
                print(f"  • Languages: {', '.join(tech['programming_language'])}")
            if tech.get('frameworks'):
                print(f"  • Frameworks: {', '.join(tech['frameworks'])}")
        
        # Email addresses
        if self.results.get('emails'):
            print(f"\n[EMAIL ADDRESSES] ({len(self.results['emails'])} found):")
            for email in self.results['emails']:
                print(f"  • {email}")
        
        # Shodan info
        if self.results.get('shodan_info'):
            shodan = self.results['shodan_info']
            print(f"\n[SHODAN INTELLIGENCE]:")
            print(f"  • Organization: {shodan.get('organization', 'Unknown')}")
            print(f"  • OS: {shodan.get('operating_system', 'Unknown')}")
            if shodan.get('vulnerabilities'):
                print(f"  • Vulnerabilities: {len(shodan['vulnerabilities'])} found")


def main():
    parser = argparse.ArgumentParser(description='Intermediate Domain Reconnaissance Toolkit')
    parser.add_argument('domain', nargs='?', help='Target domain to scan')
    parser.add_argument('-m', '--modules', nargs='+', 
                       choices=['basic', 'portscan', 'banner', 'tech', 'emails', 'shodan'],
                       help='Modules to run (default: all)')
    parser.add_argument('-o', '--output', help='Output filename')
    parser.add_argument('-f', '--format', choices=['json', 'csv'], default='json',
                       help='Report format (default: json)')
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
    recon = IntermediateRecon(domain)
    recon.run_intermediate_recon(modules=args.modules, shodan_key=args.shodan_key)
    recon.display_intermediate_results()
    recon.save_structured_report(format_type=args.format, filename=args.output)


if __name__ == "__main__":
    main()
