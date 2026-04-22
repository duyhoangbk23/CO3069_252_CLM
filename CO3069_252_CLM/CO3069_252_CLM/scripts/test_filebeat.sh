#!/bin/bash
# =============================================================================
# FILEBEAT COMPONENT TEST SCRIPT
# =============================================================================
# Validates Filebeat configuration, paths, and connectivity in isolation.
# =============================================================================

set -e

# Configuration
CONFIG_PATH="../CO3069_Assignment_CLM/configs/filebeat.yml"
LOG_DIR="${LOG_DIR:-/logs}"

echo "=== [1/3] Validating Filebeat Syntax ==="
if filebeat test config -c "$CONFIG_PATH"; then
    echo "SUCCESS: Filebeat configuration syntax is valid."
else
    echo "ERROR: Filebeat configuration syntax check failed."
    exit 1
fi

echo ""
echo "=== [2/3] Checking Log Path Accessibility ==="
# Check if the configured log directory or the default exists
if [ -d "$LOG_DIR" ]; then
    echo "SUCCESS: Log directory $LOG_DIR exists."
else
    echo "WARNING: Log directory $LOG_DIR not found. Filebeat may not find logs if not mounted."
fi

echo ""
echo "=== [3/3] Testing Output Connectivity ==="
echo "Note: This requires Logstash to be running at the configured address."
# We use -v to see details
filebeat test output -c "$CONFIG_PATH" || echo "INFO: Connectivity test failed (Expected if Logstash is offline)."

echo ""
echo "=== Filebeat Test Complete ==="
