## 1. SSH Brute Force Alert
**Trigger Condition:**  
More than 5 failed SSH login attempts from the same IP within 5 minutes.

**SPL Used:**  
index=main sourcetype=auth-2 "failed password"
| stats count by src_ip, user
| where count > 5

**Severity:** High  
**Action:** Email notification / SOC ticket creation

---

## 2. Snort Portscan Alert
**Trigger Condition:**  
Snort detects rapid sequential port probes from a single attacker IP.

**SPL Used:**  
index="portscan_detected"
| stats count by src_ip, dest_ip, dest_port
| where count > 10

**Severity:** High  
**Action:** SOC investigation

---

## 3. SQL Injection Attempt Alert
**Trigger Condition:**  
Snort logs SQL injection signatures in HTTP traffic.

**SPL Used:**  
index="SQL_Injection_Attempt_Detected"
| stats count by src_ip, dest_ip, url, signature

**Severity:** High  
**Action:** Block IP / escalate to security engineer

---

## 4. Sudo Misuse / Privilege Escalation Alert
**Trigger Condition:**  
Unauthorized sudo attempts or suspicious privilege escalation activity.

**SPL Used:**  
index=main sourcetype=linux_secure ("sudo:" OR "su:")
| table _time, host, user, command, message

**Severity:** High  
**Action:** Review user activity / check for compromise

---

## Notes
- Alerts can be configured to send email notifications.
- Alerts can be scheduled or real-time.
- Screenshots of alert triggers are stored in the /screenshots folder.
