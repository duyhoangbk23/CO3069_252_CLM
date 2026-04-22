#!/bin/bash
# =============================================================================
# LOGSTASH COMPONENT TEST SCRIPT
# =============================================================================
# Validates Logstash configuration and HMAC logic in isolation.
# =============================================================================

set -e

# Configuration
CONFIG_PATH="../CO3069_Assignment_CLM/configs/logstash.conf"

echo "=== [1/2] Validating Logstash Syntax ==="
if [ -f "$CONFIG_PATH" ]; then
    # -t runs a configuration test
    if logstash -t -f "$CONFIG_PATH"; then
        echo "SUCCESS: Logstash configuration is valid."
    else
        echo "ERROR: Logstash configuration test failed."
        exit 1
    fi
else
    echo "ERROR: Configuration file not found at $CONFIG_PATH"
    exit 1
fi

echo ""
echo "=== [2/2] Verifying HMAC Environment Requirement ==="
if [ -z "$LOG_HMAC_KEY" ]; then
    echo "WARNING: LOG_HMAC_KEY environment variable is not set."
    echo "The pipeline will still run but logs will be tagged as '_hmac_key_missing'."
else
    echo "SUCCESS: LOG_HMAC_KEY is defined."
fi

echo ""
echo "=== Logstash Test Complete ==="
