Splunk SIEM Security Use Cases – Virtual SOC Environment

Overview

This project implements multiple security detection use cases inside a virtual SIEM environment using Splunk Enterprise. It simulates a real SOC workflow by collecting logs from Linux systems and Snort IDS, analyzing them in Splunk, and generating dashboards, alerts, and reports.
The environment detects and analyzes:
TCP Port Scans
SSH Brute Force Attacks
Privilege Escalation & sudo Misuse
SQL Injection Attempts
This project was developed as part of a Master’s thesis in Cybersecurity.

Architecture

Attacker Machine (Kali/Ubuntu)
        |
        |  Malicious Traffic
        v
Snort IDS (Ubuntu VM) -----> Splunk Forwarder -----> Splunk Enterprise
        |                                              |
        |  IDS Alerts                                  | Dashboards, Alerts,
        v                                              | SPL Queries, Reports
Linux Host Logs (auth.log, sudo logs) -----------------+

Log Sources

This SIEM ingests and analyzes:
Snort IDS Alerts
Portscan detection
SQL Injection attempts
Custom Snort rules (SID 10000003, etc.)

Linux Authentication Logs
/var/log/auth.log
SSH failed logins
sudo misuse
privilege escalation attempts

SSH Brute Force Logs
Multiple failed password attempts
Source IP, port, timestamp

These logs are forwarded to Splunk using a Universal Forwarder.

Implemented Use Cases

TCP Portscan Detection (Snort)
Detects rapid sequential port probes from a single attacker IP.
SPL Query:
index="portscan_detected"
| stats count by src_ip, dest_ip, dest_port
| where count > 10

SSH Brute Force Attempt Detection
Identifies repeated failed SSH login attempts from the same IP.
SPL Query:
index=main sourcetype=auth-2 "failed password"
| stats count by src_ip, user
| where count > 5

Privilege Escalation / sudo Misuse
Detects suspicious sudo activity, incorrect password attempts, and unauthorized root access.
SPL Query:
index=main sourcetype=linux_secure ("sudo:" OR "su:")
| table _time, host, user, command, message

SQL Injection Attempt Detection (Snort)
Detects malicious HTTP requests containing SQL injection payloads.
SPL Query:
index="SQL_Injection_Attempt_Detected"
| stats count by src_ip, dest_ip, url, signature

Dashboards & Visualizations
Screenshots of dashboards and search results are available in:
/screenshots
Includes:
Portscan detection dashboard
SSH brute force detection panel
sudo misuse logs
SQL injection alerts

Alerts
Alerts are configured in Splunk for:
High-volume SSH failures
Snort portscan alerts
SQL injection attempts
Suspicious sudo activity
Alert configuration files/screenshots are stored in:
/alerts

Queries & Documentation
All SPL queries used in this project are stored in:
/queries
Additional documentation, diagrams, and thesis-related notes are stored in:
/documentation

Skills Demonstrated
SIEM configuration (Splunk Enterprise)
Log ingestion & parsing
Detection engineering
Snort IDS rule tuning
Linux security monitoring
SOC analysis & incident investigation
Dashboard and alert creation

##  Full Thesis Report
The complete academic thesis for this project is available here:
[Download Thesis Report](documentation/Thesis%20Report.docx)

