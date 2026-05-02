#!/bin/bash

# Test Log Generator for CLM System
# This script appends sample log entries to local log files to trigger alerts.

echo "--- Simulating Security Events ---"

# 1. Simulate SSH Brute Force
echo "$(date '+%b %d %H:%M:%S') my-server sshd[1234]: Failed password for root from 192.168.1.100 port 5678 ssh2" | sudo tee -a /var/log/auth.log
echo "✅ Added SSH Failed Login to /var/log/auth.log"

# 2. Simulate SQL Injection Attack
echo '192.168.1.101 - - [29/Apr/2026:10:00:01 +0700] "GET /products.php?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 200 1234 "-" "Mozilla/5.0"' | sudo tee -a /var/log/nginx/access.log
echo "✅ Added SQL Injection attempt to /var/log/nginx/access.log"

# 3. Simulate XSS Attack
echo '192.168.1.102 - - [29/Apr/2026:10:05:10 +0700] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 567 "-" "Mozilla/5.0"' | sudo tee -a /var/log/nginx/access.log
echo "✅ Added XSS attempt to /var/log/nginx/access.log"

# 4. Simulate Firewall Block
echo "Apr 29 10:10:15 my-server kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=10.0.0.50 DST=192.168.1.10 PROTO=TCP SPT=44321 DPT=23" | sudo tee -a /var/log/ufw.log
echo "✅ Added UFW Block log to /var/log/ufw.log"

echo "--- Done! Wait ~10 seconds for Filebeat to ship and Logstash to process ---"
