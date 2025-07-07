#!/usr/bin/env python3
"""
Simple Flask Web UI for Basic Reconnaissance Suite
This version works with minimal dependencies for testing
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
import json
import os
import threading
import time
from datetime import datetime

# Try to import recon modules, fall back to basic if needed
try:
    from basic_recon import BasicRecon
    BASIC_RECON_AVAILABLE = True
    USE_MOCK = False
except ImportError:
    try:
        from mock_basic_recon import MockBasicRecon as BasicRecon
        BASIC_RECON_AVAILABLE = True
        USE_MOCK = True
        print("Using mock reconnaissance for testing")
    except ImportError:
        BASIC_RECON_AVAILABLE = False
        USE_MOCK = False

app = Flask(__name__)
app.secret_key = 'reconnaissance_suite_2024'

# Global variables for tracking scans
active_scans = {}
scan_results = {}

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Start a new reconnaissance scan"""
    data = request.get_json()
    domain = data.get('domain', '').strip()
    modules = data.get('modules', [])
    shodan_key = data.get('shodan_key', '')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    if not BASIC_RECON_AVAILABLE:
        return jsonify({'error': 'Reconnaissance modules not available'}), 500
    
    # Remove protocol if present
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    # Generate scan ID
    scan_id = f"{domain}_{int(time.time())}"
    
    # Initialize scan tracking
    active_scans[scan_id] = {
        'domain': domain,
        'modules': modules,
        'status': 'starting',
        'progress': 0,
        'current_module': '',
        'start_time': datetime.now().isoformat(),
        'logs': []
    }
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan_background, 
                             args=(scan_id, domain, modules, shodan_key))
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'status': 'started'})

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    """Get scan status and progress"""
    if scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    elif scan_id in scan_results:
        return jsonify({
            'status': 'completed',
            'progress': 100,
            'results_available': True
        })
    else:
        return jsonify({'error': 'Scan not found'}), 404

@app.route('/scan_results/<scan_id>')
def scan_results_view(scan_id):
    """Get scan results"""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    else:
        return jsonify({'error': 'Results not found'}), 404

@app.route('/reports/<path:filename>')
def download_report(filename):
    """Download report files"""
    reports_dir = os.path.join(os.getcwd(), 'reports')
    if not os.path.exists(os.path.join(reports_dir, filename)):
        return jsonify({'error': 'File not found'}), 404
    return send_from_directory(reports_dir, filename, as_attachment=True)

@app.route('/scan_files/<scan_id>')
def get_scan_files(scan_id):
    """Get available files for a scan"""
    if scan_id in active_scans and 'report_files' in active_scans[scan_id]:
        return jsonify(active_scans[scan_id]['report_files'])
    return jsonify({'error': 'No files found'}), 404

def run_scan_background(scan_id, domain, modules, shodan_key):
    """Run reconnaissance scan in background"""
    try:
        # Update status
        active_scans[scan_id]['status'] = 'running'
        active_scans[scan_id]['logs'].append(f"Starting scan for {domain}")
        
        # Initialize recon
        recon = BasicRecon(domain)
        
        # Available modules with progress weights
        module_weights = {
            'subdomains': 20,
            'dns': 15,
            'whois': 15,
            'headers': 20,
            'robots': 15,
            'geoip': 15,
        }
        
        total_weight = sum(module_weights.get(m, 0) for m in modules if m in module_weights)
        if total_weight == 0:
            total_weight = 100
        current_progress = 0
        
        # Map frontend module names to backend functions
        module_mapping = {
            'basic': ['subdomains', 'dns', 'whois', 'headers', 'robots', 'geoip'],  # Full basic recon modules
            'portscan': [],  # Not available in basic recon
            'banner': [],    # Not available in basic recon
            'tech': ['headers'],  # Use headers as tech detection
            'emails': [],    # Not available in basic recon
            'shodan': [],    # Not available in basic recon
            'waf': ['headers'],  # Use headers for basic WAF detection
            'vulnscan': [],  # Not available in basic recon
            'report': [],    # Handled separately
        }
        
        # Convert frontend modules to backend modules
        backend_modules = []
        for frontend_module in modules:
            if frontend_module in module_mapping:
                backend_modules.extend(module_mapping[frontend_module])
        
        # Remove duplicates and ensure we have at least basic modules if nothing selected
        backend_modules = list(set(backend_modules))
        if not backend_modules:
            backend_modules = ['subdomains', 'dns', 'whois', 'headers', 'robots', 'geoip']
        
        active_scans[scan_id]['logs'].append(f"Mapped modules: {modules} -> {backend_modules}")
        
        # Module functions - map to individual BasicRecon methods
        module_functions = {
            'subdomains': recon.get_subdomains_crt,
            'dns': recon.get_dns_records,
            'whois': recon.get_whois_info,
            'headers': recon.get_http_headers,
            'robots': recon.get_robots_and_sitemap,
            'geoip': recon.get_geoip_info,
        }
        
        # Filter modules to only available ones
        available_modules = [m for m in backend_modules if m in module_functions]
        if not available_modules:
            available_modules = ['subdomains', 'dns', 'whois', 'headers', 'robots', 'geoip']
        
        # Run modules
        for module in available_modules:
            if module in module_functions:
                active_scans[scan_id]['current_module'] = module
                active_scans[scan_id]['logs'].append(f"Running {module} module...")
                
                try:
                    module_functions[module]()
                    active_scans[scan_id]['logs'].append(f"✓ {module} completed")
                    # Debug: log results after each module
                    if module == 'subdomains':
                        active_scans[scan_id]['logs'].append(f"Debug: Found {len(recon.results.get('subdomains', []))} subdomains")
                    elif module == 'dns':
                        active_scans[scan_id]['logs'].append(f"Debug: Found {len(recon.results.get('dns_records', {}))} DNS record types")
                except Exception as e:
                    active_scans[scan_id]['logs'].append(f"✗ {module} failed: {str(e)}")
                    import traceback
                    active_scans[scan_id]['logs'].append(f"Traceback: {traceback.format_exc()}")
                
                # Update progress
                current_progress += module_weights.get(module, 10)  # Default weight of 10
                active_scans[scan_id]['progress'] = int((current_progress / total_weight) * 100)
        
        # Save results
        scan_results[scan_id] = recon.results
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['progress'] = 100
        active_scans[scan_id]['logs'].append("Scan completed successfully!")
        
        # Save basic report with proper filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{domain}_basic_scan_{timestamp}.txt"
        json_filename = f"{domain}_basic_scan_{timestamp}.json"
        
        # Save text report
        recon.save_results(f"reports/{report_filename}")
        
        # Save JSON report for download
        with open(f"reports/{json_filename}", 'w') as f:
            json.dump(recon.results, f, indent=2, default=str)
        
        # Store filenames for download
        active_scans[scan_id]['report_files'] = {
            'text_report': report_filename,
            'json_report': json_filename
        }
        
    except Exception as e:
        active_scans[scan_id]['status'] = 'failed'
        active_scans[scan_id]['logs'].append(f"Scan failed: {str(e)}")

@app.route('/test')
def test_page():
    """Test page to verify Flask is working"""
    # Test basic recon functionality
    test_results = {}
    
    if BASIC_RECON_AVAILABLE:
        try:
            from basic_recon import BasicRecon
            test_recon = BasicRecon('example.com')
            # Quick test without network calls
            test_recon.results['subdomains'] = ['www.example.com', 'mail.example.com']  # Mock data
            test_recon.results['dns_records'] = {'A': ['93.184.216.34'], 'NS': ['a.iana-servers.net']}
            test_results = {
                'subdomains_count': len(test_recon.results['subdomains']),
                'dns_records_count': len(test_recon.results['dns_records'])
            }
        except Exception as e:
            test_results = {'error': str(e)}
    
    return jsonify({
        'status': 'Flask is working!',
        'basic_recon_available': BASIC_RECON_AVAILABLE,
        'test_results': test_results,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/debug/<scan_id>')
def debug_scan(scan_id):
    """Debug endpoint to see scan data"""
    debug_data = {}
    if scan_id in active_scans:
        debug_data['active_scan'] = active_scans[scan_id]
    if scan_id in scan_results:
        debug_data['scan_results'] = scan_results[scan_id]
    return jsonify(debug_data)

if __name__ == '__main__':
    # Ensure templates directory exists
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    print("Starting Flask application...")
    print(f"Basic recon available: {BASIC_RECON_AVAILABLE}")
    print(f"Using mock data: {USE_MOCK if BASIC_RECON_AVAILABLE else 'N/A'}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
