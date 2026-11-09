# Splunk SIEM & Log Monitoring Lab

Hands-on SOC lab using **Splunk Enterprise** on Ubuntu to detect and investigate Linux attacks, with every detection mapped to the **MITRE ATT&CK** framework.

The goal was to practise the full Tier 1 SOC workflow: ingest logs, write detections, simulate attacks, triage alerts, and document incidents.

---

## Lab Environment

| Component | Details |
|---|---|
| Hypervisor | VMware Workstation |
| OS | Ubuntu 64-bit |
| SIEM | Splunk Enterprise v10.2.1 |
| Log sources | `/var/log/auth.log` (authentication, sudo, su, SSH), `/var/log/syslog` (system events) |

---

## Detection Rules

| # | Detection | MITRE ATT&CK | What it detects |
|---|---|---|---|
| 1 | SSH Brute Force | [T1110.001 – Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | 5+ failed SSH logins from the same source |
| 2 | Successful SSH Logins | [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Successful logins, to spot valid-account use after failed attempts |
| 3 | Sudo Command Execution | [T1548.003 – Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) | Commands run with elevated privileges |
| 4 | Session Activity Monitoring | [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/) | User sessions opened and closed |
| 5 | Failed su Attempts | [T1548 – Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) | Failed attempts to switch to another user (often root) |
| 6 | Successful Login After Brute Force | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) → [T1078](https://attack.mitre.org/techniques/T1078/) | Source IP with 5+ failed SSH logins that then logs in successfully, indicating a likely compromised account |

Full SPL queries are in [`splunk-queries/`](splunk-queries/).

### Example: SSH Brute Force

```spl
index=main source="/var/log/auth.log" "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count AS failed_attempts BY src_ip, user
| where failed_attempts >= 5
| sort - failed_attempts
```

---

## Attack Simulation

Each detection was tested by generating the matching activity on the lab machine:

- **Brute force:** repeated failed SSH logins with incorrect passwords
- **Privilege escalation:** running commands with `sudo` and failed `su` attempts with wrong passwords
- **Account compromise:** a successful SSH login after 5+ failed attempts from the same source

Alerts were then triaged in Splunk to confirm they fired correctly and to tune thresholds and reduce noise.

---

## Incident Reports

Three incidents were documented using a standard SOC report format (summary, timeline, evidence, MITRE mapping, impact, recommendations). The reports are in [`incident-reports/`](incident-reports/).

---

## Key Outcomes

- Built 6 SPL detections covering credential access and privilege escalation techniques
- Mapped every detection to MITRE ATT&CK
- Validated each detection against simulated attack activity
- Produced 3 standardized incident reports

---

## Repository Structure

```
SIEM-Lab/
├── splunk-queries/     # SPL detection rules
└── incident-reports/   # Documented security incidents
```

---

## What I Learned

- How Linux authentication events appear in `auth.log` and how to parse them with `rex`
- Choosing alert thresholds that catch attacks without flooding analysts with false positives
- Mapping real log activity to MITRE ATT&CK techniques accurately
- Writing incident reports that are clear to both technical and non-technical readers

## Next Steps

- Add Windows Event Logs and Sysmon from a Windows VM
- Build a Splunk dashboard for authentication activity
- Add detections for persistence (e.g. new user creation, cron job changes)
