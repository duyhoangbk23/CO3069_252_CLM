# CLM System Test Guide

This guide describes how to verify that your Centralized Log Management system is working correctly.

## 1. Prerequisites (Điều kiện cần)

- **Docker & Docker Compose**: Installed and running.
- **Python 3.x**: Installed (for the integrity check script).
- **Resources**: At least **4GB RAM** dedicated to Docker.
- **Operating System**: Linux is recommended for the log generation script. If on Windows/Mac, you can manually add logs to the files inside the Docker volumes.
- **Dependencies**:
  ```bash
  pip install elasticsearch
  ```

## 2. Setup (Cài đặt)

Follow the README to:
1. Generate certificates using `instances.yaml`.
2. Create `.env` from `.env.example`.
3. Start the containers: `docker-compose up -d`.
4. Initialize the `kibana_system` password as described in Phase 2.

## 3. Testing Flow (Quy trình Test)

### Step A: Generate Test Logs
Run the simulation script to create "attacks" in the log files:
```bash
chmod +x generate_test_logs.sh
./generate_test_logs.sh
```

### Step B: Verify in Kibana
1. Open `https://localhost:5601` (User: `elastic`, Pass: your password).
2. Go to **Management > Stack Management > Index Patterns**.
3. Create an index pattern for `logs-*`.
4. Go to **Discover** to see the incoming logs.
5. Search for `tags : "security_alert"` to see detected SQLi or SSH failures.

### Step C: Verify Log Integrity (HMAC)
To prove that logs haven't been tampered with:
1. Find a Document ID in Kibana (click on a log entry and copy the `_id` field).
2. Run the verification script:
   ```bash
   # Syntax: python verify_log_integrity.py <index> <doc_id> <hmac_key> <elastic_password>
   python verify_log_integrity.py logs-2026.04.29 YOUR_ID_HERE YourSuperSecretKey123 YOUR_PASSWORD
   ```

## 4. Expected Results
- **Kibana**: You should see fields like `integrity.hmac`, `alert_level`, and tags like `sql_injection`.
- **Integrity Script**: Should return `SUCCESS: Integrity Verified! ✅`.
- **Security Alerts**: Check the `security-alerts-*` index to see only high-priority events.
