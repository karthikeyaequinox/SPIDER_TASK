#!/usr/bin/env python3
"""
Test script to verify module execution
"""

import sys
import os
import json
import requests

def test_flask_scan():
    """Test the Flask scan endpoint with multiple modules"""
    print("Testing Flask scan with multiple modules...")
    
    # Test data
    test_data = {
        'domain': 'example.com',
        'modules': ['basic', 'tech', 'waf'],  # Multiple modules
        'shodan_key': ''
    }
    
    try:
        # Start scan
        response = requests.post('http://127.0.0.1:5000/start_scan', 
                               json=test_data, 
                               timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result['scan_id']
            print(f"✓ Scan started with ID: {scan_id}")
            
            # Wait and check status
            import time
            time.sleep(5)
            
            status_response = requests.get(f'http://127.0.0.1:5000/scan_status/{scan_id}')
            if status_response.status_code == 200:
                status = status_response.json()
                print(f"✓ Scan status: {status.get('status', 'unknown')}")
                print(f"✓ Progress: {status.get('progress', 0)}%")
                print(f"✓ Current module: {status.get('current_module', 'none')}")
                
                if 'logs' in status:
                    print("✓ Logs:")
                    for log in status['logs'][-5:]:  # Show last 5 logs
                        print(f"  {log}")
                
                # If completed, get results
                if status.get('status') == 'completed':
                    results_response = requests.get(f'http://127.0.0.1:5000/scan_results/{scan_id}')
                    if results_response.status_code == 200:
                        results = results_response.json()
                        print(f"✓ Subdomains found: {len(results.get('subdomains', []))}")
                        print(f"✓ DNS records: {len(results.get('dns_records', {}))}")
                        print(f"✓ HTTP headers: {len(results.get('http_headers', {}))}")
                
            else:
                print(f"✗ Failed to get status: {status_response.status_code}")
        else:
            print(f"✗ Failed to start scan: {response.status_code} - {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("✗ Cannot connect to Flask app. Make sure it's running on port 5000")
    except Exception as e:
        print(f"✗ Error: {e}")

def test_basic_recon_directly():
    """Test BasicRecon class directly"""
    print("\nTesting BasicRecon class directly...")
    
    try:
        from basic_recon import BasicRecon
        
        recon = BasicRecon('example.com')
        
        # Test individual modules
        modules_to_test = [
            ('subdomains', recon.get_subdomains_crt),
            ('dns', recon.get_dns_records),
            ('whois', recon.get_whois_info),
            ('headers', recon.get_http_headers),
            ('robots', recon.get_robots_and_sitemap),
            ('geoip', recon.get_geoip_info),
        ]
        
        for module_name, module_func in modules_to_test:
            try:
                print(f"Testing {module_name} module...")
                module_func()
                print(f"✓ {module_name} module completed")
            except Exception as e:
                print(f"✗ {module_name} module failed: {e}")
        
        # Check results
        print(f"\nResults summary:")
        print(f"✓ Subdomains: {len(recon.results.get('subdomains', []))}")
        print(f"✓ DNS records: {len(recon.results.get('dns_records', {}))}")
        print(f"✓ HTTP headers: {len(recon.results.get('http_headers', {}))}")
        print(f"✓ GeoIP info: {'Yes' if recon.results.get('geoip_info') else 'No'}")
        
    except ImportError as e:
        print(f"✗ Cannot import BasicRecon: {e}")
    except Exception as e:
        print(f"✗ Error testing BasicRecon: {e}")

if __name__ == "__main__":
    print("🔧 Testing Reconnaissance Module Execution")
    print("="*50)
    
    # Test direct BasicRecon first
    test_basic_recon_directly()
    
    # Test Flask API
    test_flask_scan()
