import requests
import json
import argparse
from base64 import b64encode

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Barracuda WAF Configuration Checker")
parser.add_argument('--host', required=True, help="IP address or hostname of the Barracuda WAF")
parser.add_argument('--username', default='admin', help="Username for authentication (default: admin)")
parser.add_argument('--password', required=True, help="Password for authentication")
parser.add_argument('--api_version', default='v1', help="API version (e.g., v1 or v3.2, default: v1)")
args = parser.parse_args()

# Base URL
base_url = f"http://{args.host}:8000/restapi/{args.api_version}"

# Function to login and get token
def get_token():
    url = f"{base_url}/login"
    data = {"username": args.username, "password": args.password}
    try:
        response = requests.post(url, json=data, timeout=10)
        response.raise_for_status()
        return response.json().get('token')
    except requests.RequestException as e:
        raise Exception(f"Login failed: {str(e)}")

# Auth for requests: Basic auth with token as username and empty password
token = get_token()
auth = (token, '')

# Function to fetch data from endpoint
def fetch_config(endpoint):
    url = f"{base_url}/{endpoint}"
    try:
        response = requests.get(url, auth=auth, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Warning: Failed to fetch {endpoint}: {str(e)}")
        return None

# Logout
def logout():
    url = f"{base_url}/logout"
    try:
        requests.delete(url, auth=auth, timeout=10)
    except requests.RequestException:
        pass

# Fetch configurations (assuming endpoints based on Barracuda WAF API docs)
services = fetch_config('virtual_services') or {}
policies = fetch_config('security_policies') or {}

# Define findings list
findings = []

# Automated Check 1: Security Mode Active
issue_id = 1
issue_name = "Security Mode not set to Active"
risk = "High"
fix_type = "quick"
remediation = "Update the service security mode to 'ACTIVE' via API or web interface."
status = "Fail"
if services:
    # Handle both dict and list cases for services
    service_security = services.get('security', {}) if isinstance(services, dict) else services[0].get('security', {}) if services else {}
    if service_security.get('mode') == "ACTIVE":
        status = "Pass"
findings.append({
    'id': issue_id,
    'name': issue_name,
    'risk': risk,
    'status': status,
    'fix': fix_type,
    'remediation': remediation
})

# Automated Check 2: TLS 1.0 Disabled
issue_id += 1
issue_name = "TLS 1.0 Enabled"
risk = "High"
fix_type = "quick"
remediation = "Disable TLS 1.0 in SSL offloading settings (set enable_tls_1 to 0)."
status = "Fail"
if services:
    ssl = services.get('ssl_offloading', {}) if isinstance(services, dict) else services[0].get('ssl_offloading', {}) if services else {}
    if ssl.get('enable_tls_1') == 0:
        status = "Pass"
findings.append({
    'id': issue_id,
    'name': issue_name,
    'risk': risk,
    'status': status,
    'fix': fix_type,
    'remediation': remediation
})

# Automated Check 3: Key Attack Types Blocked
issue_id += 1
issue_name = "Insufficient Blocked Attack Types"
risk = "Medium"
fix_type = "quick"
remediation = "Ensure blocked_attack_types includes at least sql_injection, cross_site_scripting, os_command_injection."
status = "Fail"
required_attacks = ["sql_injection", "cross_site_scripting", "os_command_injection"]
if policies:
    url_prot = policies.get('url_protection', {}) if isinstance(policies, dict) else policies[0].get('url_protection', {}) if policies else {}
    blocked = url_prot.get('blocked_attack_types', [])
    if all(attack in blocked for attack in required_attacks):
        status = "Pass"
findings.append({
    'id': issue_id,
    'name': issue_name,
    'risk': risk,
    'status': status,
    'fix': fix_type,
    'remediation': remediation
})

# Automated Check 4: Cookie Tamper Proof Mode
issue_id += 1
issue_name = "Cookie Tamper Proof Mode not Secure"
risk = "Medium"
fix_type = "quick"
remediation = "Set tamper_proof_mode to 'encrypted' or 'signed' in cookie_security."
status = "Fail"
if policies:
    cookie_sec = policies.get('cookie_security', {}) if isinstance(policies, dict) else policies[0].get('cookie_security', {}) if policies else {}
    mode = cookie_sec.get('tamper_proof_mode')
    if mode in ["encrypted", "signed"]:
        status = "Pass"
findings.append({
    'id': issue_id,
    'name': issue_name,
    'risk': risk,
    'status': status,
    'fix': fix_type,
    'remediation': remediation
})

# Manual Check 5: Deployment in Proxy Mode
issue_id += 1
issue_name = "Deployment not in Proxy Mode"
risk = "High"
fix_type = "planned"
remediation = "Deploy the WAF in Proxy mode (preferably Two-Arm) for best security. Verify network configuration manually."
status = "Manual Verification Required"
findings.append({
    'id': issue_id,
    'name': issue_name,
    'risk': risk,
    'status': status,
    'fix': fix_type,
    'remediation': remediation
})

# Manual Check 6: Deployed Behind Firewall
issue_id += 1
issue_name = "Not Deployed Behind a Firewall"
risk = "Critical"
fix_type = "involved"
remediation = "Place the WAF behind a firewall and limit admin interface access. Verify network topology manually."
status = "Manual Verification Required"
findings.append({
    'id': issue_id,
    'name': issue_name,
    'risk': risk,
    'status': status,
    'fix': fix_type,
    'remediation': remediation
})

# Manual Check 7: High Availability Clustering
issue_id += 1
issue_name = "High Availability Not Configured"
risk = "Medium"
fix_type = "planned"
remediation = "Configure HA clustering for redundancy. Check cluster status manually or via system logs."
status = "Manual Verification Required"
findings.append({
    'id': issue_id,
    'name': issue_name,
    'risk': risk,
    'status': status,
    'fix': fix_type,
    'remediation': remediation
})

# Generate HTML Report with Banner
html = """
<html>
<head>
<title>Config Check Barracuda WAF</title>
<style>
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid black; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
.banner { background-color: #4CAF50; color: white; padding: 10px; text-align: center; font-size: 24px; font-weight: bold; }
</style>
</head>
<body>
<div class="banner">Config Check Barracuda WAF</div>
<h1>Barracuda WAF Configuration Report</h1>
<table>
<tr>
<th>Finding ID</th>
<th>Issue Name</th>
<th>Risk-status</th>
<th>Status</th>
<th>Fix type</th>
<th>Remediation</th>
</tr>
"""
for finding in findings:
    html += f"""
<tr>
<td>{finding['id']}</td>
<td>{finding['name']}</td>
<td>{finding['risk']}</td>
<td>{finding['status']}</td>
<td>{finding['fix']}</td>
<td>{finding['remediation']}</td>
</tr>
"""

html += """
</table>
</body>
</html>
"""

# Output the HTML to file
try:
    with open('waf_report.html', 'w') as f:
        f.write(html)
    print("Report generated: waf_report.html")
except Exception as e:
    print(f"Error writing report: {str(e)}")

# Logout
logout()
