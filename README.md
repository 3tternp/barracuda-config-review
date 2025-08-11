# barracuda-config-review

This Python script checks the configuration of a Barracuda Web Application Firewall (WAF) using its REST API and generates an HTML report detailing security findings. The report includes finding ID, issue name, risk status (Critical, High, Medium, Low), status (Pass, Fail, or Manual Verification Required), fix type (quick, planned, involved), and remediation steps.

The script performs both automated and manual verification checks for key security settings, such as security mode, TLS configuration, attack type blocking, and more. A banner titled "Config Check Barracuda WAF" is displayed in the terminal during execution and in the generated HTML report.

# Features


```
Automated Checks:

Security Mode (Active or not)

TLS 1.0 Disabled

Key Attack Types Blocked (e.g., SQL Injection, XSS)

Cookie Tamper Proof Mode
Access Logs Enabled
Cloaking Enabled
Request Limits Enabled
Parameter Protection Enabled
URL Protection Enabled
Secure Cookies Enforced
HTTP-Only Cookies Enforced
```

# Manual Verification Checks:
``
Proxy Mode Deployment
Firewall Deployment
High Availability Clustering
Syslog Configuration
Notifications Enabled
Firmware Up to Date
```

Generates an HTML report (waf_report.html) with a styled table and banner.

**Requirements**
```
Python 3.6+
Required Python package:
requests (install via pip install requests)
Access to the Barracuda WAF REST API (IP/hostname, username, password)
Network connectivity to the WAF's API endpoint (default port: 8000)
```
**Installation**

Clone the repository:
```
git clone https://github.com/3tternp/barracuda-config-review
cd barracuda-config-review
Install the required Python package:
pip install requests
```
**Usage**
Run the script from the command line with the required arguments:
python waf_check.py --host <WAF_IP> --password <PASSWORD> [--username <USERNAME>] [--api_version <VERSION>]

Example

python waf_check.py --host 192.168.1.100 --password mypassword --username admin --api_version v1

Arguments


--host: (Required) IP address or hostname of the Barracuda WAF.


--password: (Required) Password for authentication.


--username: (Optional) Username for authentication (default: admin).


--api_version: (Optional) API version (e.g., v1 or v3.2, default: v1).

Output


Terminal Output: Displays a banner ("Config Check Barracuda WAF") and status messages (e.g., "Report generated: waf_report.html").


HTML Report: Generates waf_report.html in the working directory, containing a table of findings with:


Finding ID: Unique identifier for each issue

Issue Name: Description of the configuration issue.


Risk-status: Critical, High, Medium, or Low.


Status: Pass, Fail, or Manual Verification Required.


Fix type: Quick, Planned, or Involved.



Remediation: Steps to resolve the issue.


The HTML report includes a green banner titled "Config Check Barracuda WAF".

python waf_check.py --host <WAF_IP> --password <PASSWORD> [--username <USERNAME>] [--api_version <VERSION>]

python waf_check.py --host 192.168.1.100 --password mypassword --username admin --api_version v1
