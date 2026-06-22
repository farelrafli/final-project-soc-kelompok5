#!/bin/bash
echo "=== SOCIAL ENGINEERING SIMULATION ==="

# Simulate failed logins from phishing victim credentials
for i in {1..5}; do
    logger -t sshd "Failed password for invalid user admin from 203.0.113.$i port 4444 ssh2"
    logger -t sshd "Failed password for root from 203.0.113.$i port 4444 ssh2"
done

# Simulate privilege escalation after successful phishing
logger -t sudo "azureuser : TTY=pts/0 ; PWD=/home/azureuser ; USER=root ; COMMAND=/usr/bin/passwd root"
logger -t sudo "azureuser : TTY=pts/0 ; PWD=/home/azureuser ; USER=root ; COMMAND=/usr/sbin/useradd backdoor"

# Simulate phishing payload
logger -t bash "PHISHING_SIMULATION: credential harvester executed by compromised user"
logger -t bash "PHISHING_SIMULATION: exfiltrating /etc/passwd to 203.0.113.1"

echo "[+] Social engineering simulation events logged"
