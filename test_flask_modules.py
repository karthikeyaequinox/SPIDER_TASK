#!/usr/bin/env python3
"""
Test Flask API with multiple modules
"""

import requests
import json
import time

def test_multiple_modules():
    """Test the Flask app with multiple module selection"""
    print("🔧 Testing Flask API with multiple modules...")
    
    # Test data - selecting multiple modules
    test_data = {
        'domain': 'example.com',
        'modules': ['basic', 'tech', 'waf'],  # Multiple modules selected
        'shodan_key': ''
    }
    
    try:
        print(f"Sending request with modules: {test_data['modules']}")
        
        # Start scan
        response = requests.post('http://127.0.0.1:5000/start_scan', 
                               json=test_data, 
                               timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result['scan_id']
            print(f"✅ Scan started successfully with ID: {scan_id}")
            
            # Poll status multiple times to see progress
            for i in range(10):  # Poll for up to 20 seconds
                time.sleep(2)
                
                status_response = requests.get(f'http://127.0.0.1:5000/scan_status/{scan_id}')
                if status_response.status_code == 200:
                    status = status_response.json()
                    print(f"\n--- Poll {i+1} ---")
                    print(f"Status: {status.get('status', 'unknown')}")
                    print(f"Progress: {status.get('progress', 0)}%")
                    print(f"Current module: {status.get('current_module', 'none')}")
                    
                    if 'logs' in status:
                        print("Recent logs:")
                        for log in status['logs'][-3:]:  # Show last 3 logs
                            print(f"  {log}")
                    
                    if status.get('status') == 'completed':
                        print("✅ Scan completed!")
                        break
                    elif status.get('status') == 'failed':
                        print("❌ Scan failed!")
                        break
                else:
                    print(f"❌ Failed to get status: {status_response.status_code}")
                    break
            
            # Get final results
            if status.get('status') == 'completed':
                results_response = requests.get(f'http://127.0.0.1:5000/scan_results/{scan_id}')
                if results_response.status_code == 200:
                    results = results_response.json()
                    print(f"\n📊 FINAL RESULTS:")
                    print(f"  Subdomains found: {len(results.get('subdomains', []))}")
                    print(f"  DNS record types: {len(results.get('dns_records', {}))}")
                    print(f"  HTTP headers: {len(results.get('http_headers', {}))}")
                    print(f"  GeoIP data: {'Yes' if results.get('geoip_info') else 'No'}")
                    print(f"  WHOIS data: {'Yes' if results.get('whois_info') else 'No'}")
                    
                    # Check if all expected modules ran
                    expected_data = {
                        'subdomains': results.get('subdomains', []),
                        'dns_records': results.get('dns_records', {}),
                        'http_headers': results.get('http_headers', {}),
                        'geoip_info': results.get('geoip_info', {}),
                        'whois_info': results.get('whois_info', {}),
                        'robots_txt': results.get('robots_txt', '')
                    }
                    
                    modules_with_data = [k for k, v in expected_data.items() if v]
                    print(f"\n✅ Modules that produced data: {modules_with_data}")
                    
                    if len(modules_with_data) >= 3:  # Should have at least 3 types of data
                        print("✅ SUCCESS: Multiple modules executed successfully!")
                    else:
                        print("⚠️  WARNING: May not have executed all modules")
                else:
                    print(f"❌ Failed to get results: {results_response.status_code}")
            
        else:
            print(f"❌ Failed to start scan: {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to Flask app. Make sure it's running on port 5000")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_specific_modules():
    """Test with only specific modules (not basic)"""
    print(f"\n{'='*60}")
    print("🔧 Testing with SPECIFIC modules only (tech + waf)")
    
    test_data = {
        'domain': 'example.com',
        'modules': ['tech', 'waf'],  # Only specific modules, no 'basic'
        'shodan_key': ''
    }
    
    try:
        print(f"Sending request with modules: {test_data['modules']}")
        
        response = requests.post('http://127.0.0.1:5000/start_scan', 
                               json=test_data, 
                               timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result['scan_id']
            print(f"✅ Scan started with ID: {scan_id}")
            
            # Wait for completion
            time.sleep(5)
            
            status_response = requests.get(f'http://127.0.0.1:5000/scan_status/{scan_id}')
            if status_response.status_code == 200:
                status = status_response.json()
                print(f"Final status: {status.get('status')}")
                
                if 'logs' in status:
                    print("All logs:")
                    for log in status['logs']:
                        print(f"  {log}")
                
                if status.get('status') == 'completed':
                    results_response = requests.get(f'http://127.0.0.1:5000/scan_results/{scan_id}')
                    if results_response.status_code == 200:
                        results = results_response.json()
                        print(f"\n📊 SPECIFIC MODULE RESULTS:")
                        print(f"  Subdomains: {len(results.get('subdomains', []))} (should be 0)")
                        print(f"  DNS records: {len(results.get('dns_records', {}))} (should be 0)")
                        print(f"  HTTP headers: {len(results.get('http_headers', {}))} (should be > 0)")
                        
                        if len(results.get('http_headers', {})) > 0 and len(results.get('subdomains', [])) == 0:
                            print("✅ SUCCESS: Only headers module ran as expected!")
                        else:
                            print("⚠️  Results don't match expected pattern")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    print("🧪 TESTING MULTI-MODULE EXECUTION FIX")
    print("="*60)
    
    # Test 1: Multiple modules including basic
    test_multiple_modules()
    
    # Test 2: Specific modules only
    test_specific_modules()
    
    print(f"\n{'='*60}")
    print("🏁 Testing complete!")
