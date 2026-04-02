index=main source="/var/log/auth.log" "Failed password for invalid user" 
| stats count by host 
| where count > 5
