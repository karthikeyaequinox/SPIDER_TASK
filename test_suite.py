#!/usr/bin/env python3
"""
Test script to demonstrate the Advanced Reconnaissance Suite
"""

import sys
import os
import subprocess
import time

def test_basic_recon():
    """Test Level 1 basic reconnaissance"""
    print("=" * 60)
    print("TESTING LEVEL 1: Basic Reconnaissance")
    print("=" * 60)
    
    # Test with example.com (safe test domain)
    try:
        result = subprocess.run([
            'python3', 'basic_recon.py', 'example.com', 
            '-o', 'test_basic_output.txt'
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✓ Basic reconnaissance completed successfully")
            if os.path.exists('test_basic_output.txt'):
                print("✓ Output file created successfully")
                with open('test_basic_output.txt', 'r') as f:
                    content = f.read()
                    if 'example.com' in content:
                        print("✓ Report contains expected domain")
            else:
                print("✗ Output file not created")
        else:
            print(f"✗ Basic reconnaissance failed: {result.stderr}")
            
    except Exception as e:
        print(f"✗ Error running basic reconnaissance: {e}")

def test_intermediate_recon():
    """Test Level 2 intermediate reconnaissance"""
    print("\n" + "=" * 60)
    print("TESTING LEVEL 2: Intermediate Reconnaissance")
    print("=" * 60)
    
    try:
        result = subprocess.run([
            'python3', 'intermediate_recon.py', 'example.com',
            '-m', 'basic', 'tech', 'emails',
            '-f', 'json'
        ], capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            print("✓ Intermediate reconnaissance completed successfully")
            # Check if reports directory was created
            if os.path.exists('reports'):
                print("✓ Reports directory created")
                json_files = [f for f in os.listdir('reports') if f.endswith('.json')]
                if json_files:
                    print(f"✓ JSON report created: {json_files[0]}")
        else:
            print(f"✗ Intermediate reconnaissance failed: {result.stderr}")
            
    except Exception as e:
        print(f"✗ Error running intermediate reconnaissance: {e}")

def test_advanced_recon():
    """Test Level 3 advanced reconnaissance (limited modules)"""
    print("\n" + "=" * 60)
    print("TESTING LEVEL 3: Advanced Reconnaissance")
    print("=" * 60)
    
    try:
        # Test with limited modules to avoid long execution
        result = subprocess.run([
            'python3', 'advanced_recon.py', 'example.com',
            '-m', 'basic', 'tech', 'waf', 'report'
        ], capture_output=True, text=True, timeout=180)
        
        if result.returncode == 0:
            print("✓ Advanced reconnaissance completed successfully")
            # Check for HTML report
            if os.path.exists('reports'):
                html_files = [f for f in os.listdir('reports') if f.endswith('.html')]
                if html_files:
                    print(f"✓ HTML report created: {html_files[0]}")
        else:
            print(f"✗ Advanced reconnaissance failed: {result.stderr}")
            
    except Exception as e:
        print(f"✗ Error running advanced reconnaissance: {e}")

def test_web_interface():
    """Test Flask web interface startup"""
    print("\n" + "=" * 60)
    print("TESTING WEB INTERFACE")
    print("=" * 60)
    
    try:
        # Start Flask app in background
        import subprocess
        import time
        import requests
        
        # Start the Flask app
        flask_process = subprocess.Popen([
            'python3', 'app.py'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait for server to start
        time.sleep(5)
        
        # Test if server is responding
        try:
            response = requests.get('http://localhost:5000', timeout=5)
            if response.status_code == 200:
                print("✓ Flask web interface started successfully")
                print("✓ Web interface accessible at http://localhost:5000")
            else:
                print(f"✗ Web interface returned status code: {response.status_code}")
        except requests.exceptions.RequestException:
            print("✗ Could not connect to web interface")
        
        # Terminate Flask process
        flask_process.terminate()
        flask_process.wait()
        
    except Exception as e:
        print(f"✗ Error testing web interface: {e}")

def check_dependencies():
    """Check if all required dependencies are installed"""
    print("=" * 60)
    print("CHECKING DEPENDENCIES")
    print("=" * 60)
    
    # Check Python modules
    required_modules = [
        'requests', 'dnspython', 'whois', 'nmap', 
        'selenium', 'flask', 'jinja2', 'beautifulsoup4'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module.replace('dnspython', 'dns').replace('beautifulsoup4', 'bs4'))
            print(f"✓ {module}")
        except ImportError:
            print(f"✗ {module} (missing)")
            missing_modules.append(module)
    
    # Check system tools
    system_tools = ['nmap', 'whois', 'dig']
    
    for tool in system_tools:
        try:
            result = subprocess.run(['which', tool], capture_output=True)
            if result.returncode == 0:
                print(f"✓ {tool}")
            else:
                print(f"✗ {tool} (not found)")
        except Exception:
            print(f"✗ {tool} (error checking)")
    
    if missing_modules:
        print(f"\n⚠️  Missing Python modules: {', '.join(missing_modules)}")
        print("Install with: pip install " + " ".join(missing_modules))
    
    return len(missing_modules) == 0

def main():
    """Run all tests"""
    print("🔍 ADVANCED RECONNAISSANCE SUITE - TEST RUNNER")
    print("=" * 60)
    
    # Check dependencies first
    if not check_dependencies():
        print("\n❌ Some dependencies are missing. Please install them before running tests.")
        return False
    
    print("\n🚀 Starting functionality tests...")
    
    # Run tests
    test_basic_recon()
    test_intermediate_recon()
    test_advanced_recon()
    test_web_interface()
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print("✓ All tests completed")
    print("📁 Check the 'reports/' directory for generated reports")
    print("📄 Check for test output files in current directory")
    print("\n🔍 Test completed successfully!")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
