#!/usr/bin/env python3
"""
Flask Web UI for Advanced Reconnaissance Suite
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
import json
import os
import threading
import time
from datetime import datetime
try:
    from advanced_recon import AdvancedRecon
    RECON_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Advanced recon not available: {e}")
    RECON_AVAILABLE = False

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
    return send_from_directory('reports', filename)

def run_scan_background(scan_id, domain, modules, shodan_key):
    """Run reconnaissance scan in background"""
    try:
        if not RECON_AVAILABLE:
            active_scans[scan_id]['status'] = 'failed'
            active_scans[scan_id]['logs'].append("Advanced recon module not available")
            return
            
        # Update status
        active_scans[scan_id]['status'] = 'running'
        active_scans[scan_id]['logs'].append(f"Starting scan for {domain}")
        
        # Initialize recon
        recon = AdvancedRecon(domain)
        
        # Available modules with progress weights
        module_weights = {
            'basic': 20,
            'portscan': 15,
            'banner': 10,
            'tech': 10,
            'emails': 10,
            'shodan': 5,
            'waf': 10,
            'vulnscan': 10,
            'report': 5
        }
        
        total_weight = sum(module_weights.get(m, 0) for m in modules)
        current_progress = 0
        
        # Module functions
        module_functions = {
            'basic': recon.run_recon,
            'portscan': lambda: recon.port_scan_nmap(),
            'banner': recon.banner_grabbing,
            'tech': recon.detect_technology,
            'emails': recon.harvest_emails,
            'shodan': lambda: recon.shodan_lookup(shodan_key),
            'waf': recon.detect_waf_cdn,
            'vulnscan': recon.vulnerability_scan_basic,
            'report': recon.generate_html_report
        }
        
        # Run modules
        for module in modules:
            if module in module_functions:
                active_scans[scan_id]['current_module'] = module
                active_scans[scan_id]['logs'].append(f"Running {module} module...")
                
                try:
                    module_functions[module]()
                    active_scans[scan_id]['logs'].append(f"✓ {module} completed")
                except Exception as e:
                    active_scans[scan_id]['logs'].append(f"✗ {module} failed: {str(e)}")
                
                # Update progress
                current_progress += module_weights.get(module, 0)
                active_scans[scan_id]['progress'] = int((current_progress / total_weight) * 100)
        
        # Save results
        scan_results[scan_id] = recon.results
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['progress'] = 100
        active_scans[scan_id]['logs'].append("Scan completed successfully!")
        
        # Also save structured report
        recon.save_structured_report()
        
    except Exception as e:
        active_scans[scan_id]['status'] = 'failed'
        active_scans[scan_id]['logs'].append(f"Scan failed: {str(e)}")

if __name__ == '__main__':
    # Ensure templates directory exists
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
