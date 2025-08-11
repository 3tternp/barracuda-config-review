import requests
import json
import argparse
from base64 import b64encode

# Terminal Banner
print("\n" + "*" * 50)
print(" Config Check Barracuda WAF ".center(50))
print("*" * 50 + "\n")

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
services = fetch_config('virtual_services') or {}  # or 'services'
policies = fetch_config('security_policies') or {}  # Assume default or list

# Assume default policy name is 'default' or fetch from services
default_policy_name = 'default'  # Adjust based on actual
if services and isinstance(services, dict) and 'web-firewall-policy' in services:
    default_policy_name = services['web-firewall-policy']
elif services and services:
    default_policy_name = services[0].get('web-firewall-policy', 'default')
policy_details = fetch_config(f'security_policies/{default_policy_name}') or {} if default_policy_name else {}

# Define findings list
findings = []
issue_id = 1

# Automated Check 1: Security Mode Active
issue_name = "Security Mode not set to Active"
risk = "High"
fix_type = "quick"
remediation = "Update the service security mode to 'ACTIVE' via API or web interface."
status = "Fail"
if services:
    service_security = services.get('security', {}) if isinstance(services, dict) else services[0].get('security', {}) if services else {}
    if service_security.get('mode') == "ACTIVE":
        status = "Pass"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Automated Check 2: TLS 1.0 Disabled
issue_name = "TLS 1.0 Enabled"
risk = "High"
fix_type = "quick"
remediation = "Disable TLS 1.0 in SSL offloading settings (set enable_tls_1 to 0)."
status = "Fail"
if services:
    ssl = services.get('ssl_offloading', {}) if isinstance(services, dict) else services[0].get('ssl_offloading', {}) if services else {}
    if ssl.get('enable_tls_1') == 0:
        status = "Pass"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Automated Check 3: Key Attack Types Blocked
issue_name = "Insufficient Blocked Attack Types"
risk = "Medium"
fix_type = "quick"
remediation = "Ensure blocked_attack_types includes at least sql_injection, cross_site_scripting, os_command_injection, xml_external_entities, http_protocol_violations."
status = "Fail"
required_attacks = ["sql_injection", "cross_site_scripting", "os_command_injection", "xml_external_entities", "http_protocol_violations"]
if policies or policy_details:
    config = policies if policies else policy_details
    url_prot = config.get('url_protection', {}) if isinstance(config, dict) else config[0].get('url_protection', {}) if config else {}
    blocked = url_prot.get('blocked_attack_types', [])
    if all(attack in blocked for attack in required_attacks):
        status = "Pass"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Automated Check 4: Cookie Tamper Proof Mode
issue_name = "Cookie Tamper Proof Mode not Secure"
risk = "Medium"
fix_type = "quick"
remediation = "Set tamper_proof_mode to 'encrypted' or 'signed' in cookie_security."
status = "Fail"
if policies or policy_details:
    config = policies if policies else policy_details
    cookie_sec = config.get('cookie_security', {}) if isinstance(config, dict) else config[0].get('cookie_security', {}) if config else {}
    mode = cookie_sec.get('tamper_proof_mode')
    if mode in ["encrypted", "signed"]:
        status = "Pass"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Additional Automated Check: Enable Access Logs
issue_name = "Access Logs Not Enabled"
risk = "Medium"
fix_type = "quick"
remediation = "Set enable-access-logs to 'Yes' in service configuration."
status = "Fail"
if services:
    access_logs = services.get('enable-access-logs') if isinstance(services, dict) else services[0].get('enable-access-logs') if services else None
    if access_logs == "Yes":
        status = "Pass"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Additional Automated Check: Cloaking Enabled
issue_name = "Cloaking Not Enabled"
risk = "Medium"
fix_type = "quick"
remediation = "Enable cloaking by setting filter-response-header to 'Yes' and configure headers to filter in security policy."
status = "Fail"
if policy_details:
    cloaking = policy_details.get('cloaking', {})
    if cloaking.get('filter_response_header') == "Yes":
        status = "Pass"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Additional Automated Check: Request Limits Enabled
issue_name = "Request Limits Not Enabled"
risk = "High"
fix_type = "quick"
remediation = "Enable request limits in security policy to prevent abuse (set enable to 'Yes')."
status = "Fail"
if policy_details:
    req_limits = policy_details.get('request_limits', {})
    if req_limits.get('enable') == "Yes":
        status = "Pass"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Additional Automated Check: Parameter Protection Enabled
issue_name = "Parameter Protection Not Enabled"
risk = "High"
fix_type = "quick"
remediation = "Enable parameter protection in security policy (set enable to 'Yes')."
status = "Fail"
if policy_details:
    param_prot = policy_details.get('parameter_protection', {})
    if param_prot.get('enable') == "Yes":
        status = "Pass"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Additional Automated Check: URL Protection Enabled
issue_name = "URL Protection Not Enabled"
risk = "High"
fix_type = "quick"
remediation = "Enable URL protection in security policy (set enable to 'Yes')."
status = "Fail"
if policy_details:
    url_prot = policy_details.get('url_protection', {})
    if url_prot.get('enable') == "Yes":
        status = "Pass"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Additional Automated Check: Secure Cookies
issue_name = "Secure Cookies Not Enforced"
risk = "Medium"
fix_type = "quick"
remediation = "Set secure_cookie to 'Yes' in cookie_security to enforce secure cookies over HTTPS."
status = "Fail"
if policies or policy_details:
    config = policies if policies else policy_details
    cookie_sec = config.get('cookie_security', {}) if isinstance(config, dict) else config[0].get('cookie_security', {}) if config else {}
    if cookie_sec.get('secure_cookie') == "Yes":
        status = "Pass"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Additional Automated Check: HTTP Only Cookies
issue_name = "HTTP Only Cookies Not Enforced"
risk = "Medium"
fix_type = "quick"
remediation = "Set http_only to 'Yes' in cookie_security to prevent client-side script access."
status = "Fail"
if policies or policy_details:
    config = policies if policies else policy_details
    cookie_sec = config.get('cookie_security', {}) if isinstance(config, dict) else config[0].get('cookie_security', {}) if config else {}
    if cookie_sec.get('http_only') == "Yes":
        status = "Pass"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Manual Check 5: Deployment in Proxy Mode
issue_name = "Deployment not in Proxy Mode"
risk = "High"
fix_type = "planned"
remediation = "Deploy the WAF in Proxy mode (preferably Two-Arm) for best security. Verify network configuration manually."
status = "Manual Verification Required"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Manual Check 6: Deployed Behind Firewall
issue_name = "Not Deployed Behind a Firewall"
risk = "Critical"
fix_type = "involved"
remediation = "Place the WAF behind a firewall and limit admin interface access. Verify network topology manually."
status = "Manual Verification Required"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Manual Check 7: High Availability Clustering
issue_name = "High Availability Not Configured"
risk = "Medium"
fix_type = "planned"
remediation = "Configure HA clustering for redundancy. Check cluster status manually or via system logs."
status = "Manual Verification Required"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Additional Manual Check: Syslog Configured
issue_name = "Syslog Not Configured"
risk = "Medium"
fix_type = "quick"
remediation = "Configure syslog servers for log export. Verify via ADVANCED > Export Logs manually."
status = "Manual Verification Required"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Additional Manual Check: Notifications Enabled
issue_name = "Notifications Not Enabled"
risk = "Low"
fix_type = "quick"
remediation = "Configure email notifications for events and thresholds. Verify via BASIC > Notifications manually."
status = "Manual Verification Required"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

# Additional Manual Check: Firmware Up to Date
issue_name = "Firmware Not Up to Date"
risk = "Critical"
fix_type = "planned"
remediation = "Check current firmware version against the latest from Barracuda support and update if necessary. Verify manually."
status = "Manual Verification Required"
findings.append({'id': issue_id, 'name': issue_name, 'risk': risk, 'status': status, 'fix': fix_type, 'remediation': remediation})
issue_id += 1

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
