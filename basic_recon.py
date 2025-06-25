#!/usr/bin/env python3
"""
Basic Reconnaissance Tool
Level 1: Automate fundamental recon tasks for domain information gathering
"""

import sys
import argparse
import requests
import socket
import subprocess
import json
import whois
import dns.resolver
from datetime import datetime
import re

class BasicRecon:
    def __init__(self, domain):
        self.domain = domain
        self.results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'dns_records': {},
            'whois_info': {},
            'http_headers': {},
            'robots_txt': '',
            'sitemap_xml': '',
            'geoip_info': {}
        }
    
    def get_subdomains_crt(self):
        """Get subdomains using crt.sh API"""
        print(f"[+] Enumerating subdomains for {self.domain} using crt.sh...")
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # Handle multiple domains in name_value
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain and '*' not in subdomain:
                            subdomains.add(subdomain)
                
                self.results['subdomains'] = sorted(list(subdomains))
                print(f"[+] Found {len(subdomains)} subdomains")
            else:
                print(f"[-] Failed to get subdomains from crt.sh: {response.status_code}")
        except Exception as e:
            print(f"[-] Error getting subdomains: {e}")
    
    def get_dns_records(self):
        """Get DNS records (A, NS, MX)"""
        print(f"[+] Looking up DNS records for {self.domain}...")
        record_types = ['A', 'NS', 'MX', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                records = []
                for answer in answers:
                    records.append(str(answer))
                self.results['dns_records'][record_type] = records
                print(f"[+] {record_type} records: {len(records)}")
            except dns.resolver.NXDOMAIN:
                print(f"[-] Domain {self.domain} does not exist")
                break
            except dns.resolver.NoAnswer:
                self.results['dns_records'][record_type] = []
            except Exception as e:
                print(f"[-] Error getting {record_type} records: {e}")
                self.results['dns_records'][record_type] = []
    
    def get_whois_info(self):
        """Get WHOIS information"""
        print(f"[+] Getting WHOIS information for {self.domain}...")
        try:
            w = whois.whois(self.domain)
            # Convert whois object to dict, handling datetime objects
            whois_dict = {}
            for key, value in w.__dict__.items():
                if isinstance(value, datetime):
                    whois_dict[key] = value.isoformat()
                elif isinstance(value, list):
                    whois_dict[key] = [str(v) for v in value]
                else:
                    whois_dict[key] = str(value) if value else None
            
            self.results['whois_info'] = whois_dict
            print(f"[+] WHOIS information retrieved")
        except Exception as e:
            print(f"[-] Error getting WHOIS info: {e}")
            # Fallback to CLI whois command
            try:
                result = subprocess.run(['whois', self.domain], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    self.results['whois_info']['raw'] = result.stdout
                    print(f"[+] WHOIS information retrieved via CLI")
            except Exception as cli_e:
                print(f"[-] CLI WHOIS also failed: {cli_e}")
    
    def get_http_headers(self):
        """Get HTTP headers and server banners"""
        print(f"[+] Getting HTTP headers for {self.domain}...")
        protocols = ['http', 'https']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{self.domain}"
                response = requests.head(url, timeout=10, allow_redirects=True)
                self.results['http_headers'][protocol] = dict(response.headers)
                print(f"[+] {protocol.upper()} headers retrieved (Status: {response.status_code})")
            except Exception as e:
                print(f"[-] Error getting {protocol} headers: {e}")
                self.results['http_headers'][protocol] = {}
    
    def get_robots_and_sitemap(self):
        """Get robots.txt and sitemap.xml content"""
        print(f"[+] Checking robots.txt and sitemap.xml for {self.domain}...")
        
        # Check robots.txt
        try:
            robots_url = f"https://{self.domain}/robots.txt"
            response = requests.get(robots_url, timeout=10)
            if response.status_code == 200:
                self.results['robots_txt'] = response.text
                print(f"[+] robots.txt found")
            else:
                print(f"[-] robots.txt not found (Status: {response.status_code})")
        except Exception as e:
            print(f"[-] Error getting robots.txt: {e}")
        
        # Check sitemap.xml
        try:
            sitemap_url = f"https://{self.domain}/sitemap.xml"
            response = requests.get(sitemap_url, timeout=10)
            if response.status_code == 200:
                self.results['sitemap_xml'] = response.text
                print(f"[+] sitemap.xml found")
            else:
                print(f"[-] sitemap.xml not found (Status: {response.status_code})")
        except Exception as e:
            print(f"[-] Error getting sitemap.xml: {e}")
    
    def get_geoip_info(self):
        """Get GeoIP information using free API"""
        print(f"[+] Getting GeoIP information for {self.domain}...")
        try:
            # First get the IP address
            ip = socket.gethostbyname(self.domain)
            print(f"[+] Domain IP: {ip}")
            
            # Use ipapi.co for geolocation (free tier)
            geo_url = f"https://ipapi.co/{ip}/json/"
            response = requests.get(geo_url, timeout=10)
            if response.status_code == 200:
                self.results['geoip_info'] = response.json()
                geo_data = self.results['geoip_info']
                print(f"[+] Location: {geo_data.get('city', 'Unknown')}, {geo_data.get('country_name', 'Unknown')}")
            else:
                print(f"[-] Failed to get GeoIP info: {response.status_code}")
        except Exception as e:
            print(f"[-] Error getting GeoIP info: {e}")
    
    def run_recon(self):
        """Run all reconnaissance modules"""
        print(f"\n{'='*60}")
        print(f"Starting Basic Reconnaissance for: {self.domain}")
        print(f"{'='*60}")
        
        self.get_subdomains_crt()
        self.get_dns_records()
        self.get_whois_info()
        self.get_http_headers()
        self.get_robots_and_sitemap()
        self.get_geoip_info()
        
        print(f"\n{'='*60}")
        print("Reconnaissance completed!")
        print(f"{'='*60}")
    
    def display_results(self):
        """Display results in terminal"""
        print(f"\n{'='*60}")
        print(f"RECONNAISSANCE RESULTS FOR: {self.domain}")
        print(f"{'='*60}")
        
        # Subdomains
        print(f"\n[SUBDOMAINS] ({len(self.results['subdomains'])} found):")
        for subdomain in self.results['subdomains'][:20]:  # Show first 20
            print(f"  • {subdomain}")
        if len(self.results['subdomains']) > 20:
            print(f"  ... and {len(self.results['subdomains']) - 20} more")
        
        # DNS Records
        print(f"\n[DNS RECORDS]:")
        for record_type, records in self.results['dns_records'].items():
            if records:
                print(f"  {record_type}:")
                for record in records:
                    print(f"    • {record}")
        
        # HTTP Headers
        print(f"\n[HTTP HEADERS]:")
        for protocol, headers in self.results['http_headers'].items():
            if headers:
                print(f"  {protocol.upper()}:")
                for key, value in list(headers.items())[:5]:  # Show first 5 headers
                    print(f"    • {key}: {value}")
        
        # GeoIP Info
        if self.results['geoip_info']:
            geo = self.results['geoip_info']
            print(f"\n[GEOLOCATION]:")
            print(f"  • IP: {geo.get('ip', 'Unknown')}")
            print(f"  • Country: {geo.get('country_name', 'Unknown')}")
            print(f"  • City: {geo.get('city', 'Unknown')}")
            print(f"  • ISP: {geo.get('org', 'Unknown')}")
        
        # WHOIS Info (basic)
        if self.results['whois_info']:
            print(f"\n[WHOIS INFO]:")
            whois_info = self.results['whois_info']
            if 'registrar' in whois_info:
                print(f"  • Registrar: {whois_info['registrar']}")
            if 'creation_date' in whois_info:
                print(f"  • Created: {whois_info['creation_date']}")
            if 'expiration_date' in whois_info:
                print(f"  • Expires: {whois_info['expiration_date']}")
    
    def save_results(self, filename=None):
        """Save results to file"""
        if not filename:
            filename = f"{self.domain}_basic.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write(f"Basic Reconnaissance Report for: {self.domain}\n")
                f.write(f"Generated on: {self.results['timestamp']}\n")
                f.write("="*60 + "\n\n")
                
                # Write detailed results
                f.write(f"SUBDOMAINS ({len(self.results['subdomains'])} found):\n")
                for subdomain in self.results['subdomains']:
                    f.write(f"  • {subdomain}\n")
                f.write("\n")
                
                f.write("DNS RECORDS:\n")
                for record_type, records in self.results['dns_records'].items():
                    if records:
                        f.write(f"  {record_type}:\n")
                        for record in records:
                            f.write(f"    • {record}\n")
                f.write("\n")
                
                f.write("HTTP HEADERS:\n")
                for protocol, headers in self.results['http_headers'].items():
                    if headers:
                        f.write(f"  {protocol.upper()}:\n")
                        for key, value in headers.items():
                            f.write(f"    • {key}: {value}\n")
                f.write("\n")
                
                if self.results['geoip_info']:
                    geo = self.results['geoip_info']
                    f.write("GEOLOCATION:\n")
                    f.write(f"  • IP: {geo.get('ip', 'Unknown')}\n")
                    f.write(f"  • Country: {geo.get('country_name', 'Unknown')}\n")
                    f.write(f"  • City: {geo.get('city', 'Unknown')}\n")
                    f.write(f"  • ISP: {geo.get('org', 'Unknown')}\n")
                    f.write("\n")
                
                if self.results['robots_txt']:
                    f.write("ROBOTS.TXT:\n")
                    f.write(self.results['robots_txt'])
                    f.write("\n\n")
                
                if self.results['sitemap_xml']:
                    f.write("SITEMAP.XML:\n")
                    f.write(self.results['sitemap_xml'][:1000])  # Truncate if too long
                    if len(self.results['sitemap_xml']) > 1000:
                        f.write("\n... (truncated)")
                    f.write("\n\n")
            
            print(f"[+] Results saved to: {filename}")
        except Exception as e:
            print(f"[-] Error saving results: {e}")


def main():
    parser = argparse.ArgumentParser(description='Basic Domain Reconnaissance Tool')
    parser.add_argument('domain', nargs='?', help='Target domain to scan')
    parser.add_argument('-o', '--output', help='Output file name')
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
    recon = BasicRecon(domain)
    recon.run_recon()
    recon.display_results()
    recon.save_results(args.output)


if __name__ == "__main__":
    main()
