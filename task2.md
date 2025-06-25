CyberSecurity:
Level 1: Basic Recon Automation

Objective: Automate fundamental recon tasks to replace manual steps. Make a Python tool that
automatically finds basic information about a Domain.

Steps & Tasks:

    Domain Input : Accept a domain via CLI argument or prompt.
    Subdomain Enumeration : Use:

○ crt.sh API (API Docs),

○ Sublist3r (GitHub).

    DNS Record Lookup : Retrieve A, NS, MX records using:

○ dnspython (Documentation),

○ dnsrecon (GitHub).

    WHOIS Information : Fetch via:

○ python-whois (PyPI),

○ CLI fallback to whois command.

    HTTP Headers: Fetch and display server banners using requests or curl -I.
    robots.txt & sitemap.xml: Retrieve and display /robots.txt and /sitemap.xml
    content.
    GeoIP Lookup: Determine server location using a free IP geolocation API.
    Output: Display results on terminal or write to basic_.txt.

Deliverables:

● basic_recon.py script

● Sample output file (e.g., example.com_basic.txt or screenshot of terminal
with results)
● README.md with setup instructions and usage guide

Level 2: Intermediate Recon Toolkit

Objective: Extend Level 1 by adding deeper scanning, intelligence gathering, and structured
reporting.

Steps & Tasks:

    Modular Script: Use Python with argparse to enable/disable modules individually.
    Port Scanning & Banner Grabbing:

○ Perform port scanning using nmap (with python-nmap) or masscan.

○ Extract banners using --script=banner or socket connections.

    Technology Detection: Identify web technologies using WhatWeb or Wappalyzer API.
    Email Harvesting: Use theHarvester or implement Google/Bing scraping for email
    IDs.
    Shodan Lookup: Query Shodan API for detailed open service info.
    Structured Report: Export all gathered data in JSON or CSV format to
    reports/.json or .csv.

Deliverables:

● intermediate_recon.py script

● Sample structured report (example.com_report.json or .csv)

● Updated README.md with command-line arguments and example usage

Level 3: Advanced Recon Suite

Objective: Package the toolkit into a polished, professional-grade tool with a focus on reporting,
UX, and automation. Bonus features include Web UI and Dockerization.

Level 3: Advanced Recon Suite

Objective: Package the toolkit into a polished, professional-grade tool with a focus on reporting,
UX, and automation. Bonus features include Web UI and Dockerization.

Steps & Tasks:

    Live Screenshots Module:

○ Capture live screenshots of discovered subdomains using gowitness or
Selenium.

○ Save to reports/screenshots/<domain>_<timestamp>.png.

    WAF/CDN Detection:

○ Identify Web Application Firewalls and CDN services using wafw00f and HTTP
header analysis.

○ Store findings in a dedicated security section in the final report.

    Vulnerability Scanning (Optional):

○ Use tools like Nikto or OpenVAS for basic vulnerability scanning.

○ Summarize critical findings in reports/vuln/summary.csv.

    Report Generation:

○ Export final recon summary as a well-designed HTML report using Jinja2,
Markdown + grip, or static templates.

○ Include sections for each module with visual elements (charts, tables, collapsible
panels).

Bonus :

Flask Web UI:

● Create a web dashboard using Flask:

○ Input domain and select modules through the interface

○ View live logs and status

○ Navigate structured recon results in browser

● Structure:

○ Templates in templates/

○ Static assets in static/

○ Flask routes in app.py

Dockerization:

● Dockerize the tool for seamless deployment and portability:

○ Add a Dockerfile to install all dependencies

Deliverables:

● your_tool_name/ directory with all code and modules

● Final HTML report template and output samples

● README.md including:

○ Setup, dependencies, and installation

○ Description of all modules and their usage

○ Bonus section for Flask Web UI and Docker (optional)

● Screenshots or usage video (optional but encouraged)
