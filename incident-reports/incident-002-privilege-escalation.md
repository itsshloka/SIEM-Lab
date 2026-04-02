# Incident Report 002 - Privilege Escalation
Date: 2026-04-01
Analyst: Shloka Joshi
Severity: High
MITRE ATT&CK: T1068 - Privilege Escalation

## Summary
Multiple sudo commands detected from user sj on Ubuntu host, indicating privilege escalation activity.

## Timeline
- 22:07:50 - First sudo command detected
- 22:08:14 - sudo chmod executed on auth.log
- 22:31:22 - sudo ls /root executed

## Detection
Splunk alert fired after detecting sudo COMMAND entries in auth.log.

## Root Cause
User sj executed multiple sudo commands during SIEM lab setup and testing.

## Impact
No unauthorized access. Commands were executed by legitimate admin user during lab setup.

## Remediation
- Restrict sudo access to specific commands only
- Implement sudo logging and alerting for all privileged commands
- Review sudoers file regularly

## Lessons Learned
Detection rule successfully captured all sudo activity. Any unauthorized sudo usage would be immediately detected.
