# Incident Report 001 - Brute Force Attack
Date: 2026-04-01
Analyst: Shloka Joshi
Severity: High
MITRE ATT&CK: T1110 - Brute Force

## Summary
Multiple failed SSH login attempts detected against the Ubuntu host from 127.0.0.1 targeting an invalid user account.

## Timeline
- 22:20:30 - First failed SSH attempt detected
- 22:20:32 - 10+ failed attempts within 2 seconds
- 22:20:32 - Splunk alert triggered: T1110 Brute Force Detection

## Detection
Splunk alert fired after detecting more than 5 failed password attempts for invalid user from the same source IP within one hour.

## Root Cause
Simulated brute force attack using SSH loop targeting invalid_user@localhost to test detection capability.

## Impact
No successful compromise. All attempts were denied with Permission denied.

## Remediation
- Block offending IP using UFW: ufw deny from src_ip
- Enable fail2ban to automatically block brute force attempts
- Enforce SSH key-based authentication only

## Lessons Learned
Detection rule successfully identified brute force pattern. MTTD was under 1 minute.
