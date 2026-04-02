# Incident Report 003 - Account Enumeration
Date: 2026-04-01
Analyst: Shloka Joshi
Severity: Medium
MITRE ATT&CK: T1078 - Valid Accounts

## Summary
High volume of session open and close events detected on Ubuntu host indicating possible account enumeration activity.

## Timeline
- 22:20:30 - Spike in session activity detected
- 22:20:32 - 55+ session events recorded within minutes
- 22:20:32 - Splunk alert triggered: T1078 Account Enumeration Detection

## Detection
Splunk alert fired after detecting more than 3 session open or close events from same host within one hour.

## Root Cause
Simulated account enumeration using SSH login attempts and session activity during lab testing.

## Impact
No unauthorized access. All session activity was part of controlled lab simulation.

## Remediation
- Monitor and alert on unusual session activity
- Implement account lockout policies
- Review and restrict user account permissions regularly

## Lessons Learned
Detection rule successfully identified abnormal session activity. Baseline normal activity to reduce false positives.
