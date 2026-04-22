#!/bin/bash
# =============================================================================
# COMBINED E2E PIPELINE TEST SCRIPT
# =============================================================================
# Validates the flow: Filebeat -> Logstash config with live log injection.
# =============================================================================

set -e

# Setup Workspace
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FB_CONFIG="${PROJECT_ROOT}/CO3069_Assignment_CLM/configs/filebeat.yml"
LS_CONFIG="${PROJECT_ROOT}/CO3069_Assignment_CLM/configs/logstash.conf"

TEST_DIR="/tmp/e2e_test_$$"
TEST_LOG="${TEST_DIR}/auth.log"
LS_OUT="${TEST_DIR}/logstash_stdout.log"

export LOG_HMAC_KEY="test-key-123"
export LOG_DEBUG="true"
export LOG_DIR="$TEST_DIR"
export LOGSTASH_HOST="localhost"
export LOGSTASH_PORT="5044"
export LOGSTASH_SSL_ENABLED="false"

mkdir -p "$TEST_DIR"
touch "$TEST_LOG"

cleanup() {
    echo "Cleaning up..."
    kill $(jobs -p) 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "=== [1/4] Starting Logstash in background ==="
logstash -f "$LS_CONFIG" --path.settings /etc/logstash > "$LS_OUT" 2>&1 &
echo "Waiting for Logstash to bind to port 5044..."
sleep 15

echo "=== [2/4] Starting Filebeat in background ==="
filebeat -c "$FB_CONFIG" -e -once > /dev/null 2>&1 &
FB_PID=$!

echo "=== [3/4] Injecting Sample Security Log ==="
# SSH Failed password sample
echo "$(date +'%b %d %H:%M:%S') localhost sshd[999]: Failed password for invalid user admin from 1.2.3.4 port 5678 ssh2" >> "$TEST_LOG"

echo "Waiting for processing (10s)..."
sleep 10

echo "=== [4/4] Verifying HMAC and Parsing Results ==="
if grep -q "integrity" "$LS_OUT"; then
    echo "SUCCESS: HMAC integrity field detected in Logstash output!"
    grep "integrity" "$LS_OUT" | head -n 1
else
    echo "ERROR: HMAC field not found in output. Check $LS_OUT for details."
    tail -n 20 "$LS_OUT"
    exit 1
fi

if grep -q "ssh_failed_login" "$LS_OUT"; then
    echo "SUCCESS: Security alert tag 'ssh_failed_login' detected!"
else
    echo "ERROR: Parsing failed to detect security alert."
    exit 1
fi

echo ""
echo "=== E2E Pipeline Test Passed Successfully ==="
