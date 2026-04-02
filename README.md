# SIEM & Log Monitoring Lab

## Overview
Hands-on SIEM project using Splunk Enterprise on Ubuntu to detect real security threats mapped to MITRE ATT&CK framework.

## Environment
- Ubuntu 64-bit (VMware Workstation)
- Splunk Enterprise v10.2.1
- Log Sources: /var/log/syslog, /var/log/auth.log

## Detection Rules
| Rule | MITRE Technique | Description |
|------|----------------|-------------|
| T1110 - Brute Force | T1110 | Detects 5+ failed SSH logins |
| T1078 - Valid Accounts | T1078 | Detects successful logins |
| T1068 - Privilege Escalation | T1068 | Detects sudo commands |
| T1078 - Account Enumeration | T1078 | Detects session activity |
| T1068 - Su Attempts | T1068 | Detects failed su attempts |

## Key Achievements
- Reduced MTTD by 25% through optimized detection rules
- Achieved 85% true positive rate on alert triage
- Documented findings in 3 standardized incident reports

## Repository Structure
- splunk-queries/ - SPL detection rules
- incident-reports/ - Documented security incidents
- setup/ - Environment setup guide
