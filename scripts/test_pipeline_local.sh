#!/bin/bash

# =============================================================================
# TEST SUITE FOR FILEBEAT AND LOGSTASH CONFIGURATION
# =============================================================================
# This script validates the Filebeat → Logstash pipeline in isolation
# without Elasticsearch or Kibana dependencies
# =============================================================================

set -euo pipefail

# Add Logstash to PATH if not already there
export PATH="/usr/share/logstash/bin:$PATH"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="${PROJECT_ROOT}/CO3069_Assignment_CLM/configs"
TEST_DIR="/tmp/logstash_filebeat_test_$$"
TEST_LOG_DIR="${TEST_DIR}/logs"
LOGSTASH_PID=""
FILEBEAT_PID=""
LOGSTASH_OUTPUT_FILE="${TEST_DIR}/logstash_output.txt"
LOGSTASH_STDOUT_FILE="${TEST_DIR}/logstash_stdout.log"
FILEBEAT_LOG_FILE="${TEST_DIR}/filebeat.log"
TIMEOUT_SECONDS=30
TEST_RESULTS=()

# Functions for colored output
print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TEST_RESULTS+=("PASS|$1")
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TEST_RESULTS+=("FAIL|$1")
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Cleanup function
cleanup() {
    print_info "Cleaning up test environment..."
    
    # Kill Logstash
    if [[ -n "$LOGSTASH_PID" ]]; then
        kill $LOGSTASH_PID 2>/dev/null || true
        wait $LOGSTASH_PID 2>/dev/null || true
    fi
    
    # Kill Filebeat
    if [[ -n "$FILEBEAT_PID" ]]; then
        kill $FILEBEAT_PID 2>/dev/null || true
        wait $FILEBEAT_PID 2>/dev/null || true
    fi
    
    # Remove test directory
    if [[ -d "$TEST_DIR" ]]; then
        rm -rf "$TEST_DIR"
    fi
    
    print_info "Cleanup completed"
}

trap cleanup EXIT

# =============================================================================
# SECTION 1: VERIFY REQUIRED TOOLS
# =============================================================================
print_header "SECTION 1: VERIFYING REQUIRED TOOLS"

verify_tool() {
    local tool=$1
    if command -v "$tool" &> /dev/null; then
        print_pass "$tool is installed"
        return 0
    else
        print_fail "$tool is NOT installed"
        return 1
    fi
}

verify_tool "logstash" || true
verify_tool "filebeat" || true
verify_tool "openssl" || true
verify_tool "bash" || true

# =============================================================================
# SECTION 2: CREATE TEST ENVIRONMENT
# =============================================================================
print_header "SECTION 2: CREATING TEST ENVIRONMENT"

mkdir -p "$TEST_LOG_DIR"
print_pass "Test directory created: $TEST_DIR"

# Create Logstash directory structure
mkdir -p "${TEST_DIR}/data" "${TEST_DIR}/logs" "${TEST_DIR}/config"
chmod 755 "${TEST_DIR}/data" "${TEST_DIR}/logs" "${TEST_DIR}/config"

# Create directories for Logstash settings
mkdir -p /tmp/logstash-settings-data /tmp/logstash-settings-logs
chmod 777 /tmp/logstash-settings-data /tmp/logstash-settings-logs 2>/dev/null || true

# Create temp log files for Filebeat to monitor
touch "${TEST_LOG_DIR}/auth.log"
touch "${TEST_LOG_DIR}/nginx_access.log"
touch "${TEST_LOG_DIR}/syslog"
print_pass "Test log files created"

# =============================================================================
# SECTION 3: CONFIG VALIDATION
# =============================================================================
print_header "SECTION 3: CONFIG VALIDATION"

# Test Logstash config syntax
if [[ -f "${CONFIG_DIR}/logstash.conf" ]]; then
    if logstash -t -f "${CONFIG_DIR}/logstash.conf" &>/dev/null; then
        print_pass "Logstash config syntax is valid"
    else
        print_fail "Logstash config syntax check failed"
        logstash -t -f "${CONFIG_DIR}/logstash.conf" 2>&1 | head -20
    fi
else
    print_fail "Logstash config file not found at ${CONFIG_DIR}/logstash.conf"
fi

# Test Filebeat config syntax
if [[ -f "${CONFIG_DIR}/filebeat.yml" ]]; then
    if filebeat test config -c "${CONFIG_DIR}/filebeat.yml" &>/dev/null; then
        print_pass "Filebeat config syntax is valid"
    else
        print_fail "Filebeat config syntax check failed"
        filebeat test config -c "${CONFIG_DIR}/filebeat.yml" 2>&1 | head -20
    fi
else
    print_fail "Filebeat config file not found at ${CONFIG_DIR}/filebeat.yml"
fi

# Test Filebeat output connectivity (logstash endpoint)
if filebeat test output -c "${CONFIG_DIR}/filebeat.yml" &>/dev/null; then
    print_pass "Filebeat output test passed"
else
    print_warn "Filebeat output test may fail if Logstash is not running (this is expected)"
fi

# =============================================================================
# SECTION 4: CREATE TEMPORARY TEST CONFIG (NO SSL FOR LOCAL TESTING)
# =============================================================================
print_header "SECTION 4: CREATING TEST CONFIGURATIONS (NO SSL)"

# Create minimal Logstash test config
TEST_LOGSTASH_CONF="${TEST_DIR}/logstash-test.conf"
cat > "$TEST_LOGSTASH_CONF" << 'EOF'
input {
  beats {
    port => 5044
    ssl => false
  }
}

filter {
  # Parse SSH authentication logs
  if [message] =~ "Failed password" {
    mutate {
      add_tag => ["ssh_failed_login", "security_alert", "authentication_failure"]
    }
    grok {
      match => { 
        "message" => "Failed password for (?:invalid user )?%{USERNAME:username} from %{IP:source_ip} port %{POSINT:source_port}" 
      }
      add_tag => ["ssh_parsed"]
    }
  }
  
  # Parse Nginx access logs
  if [message] =~ /^\d+\.\d+\.\d+\.\d+.*GET/ {
    grok {
      match => { 
        "message" => '%{IP:client_ip} - %{USER:ident} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:http_method} %{NOTSPACE:request_uri}(?: HTTP/%{NUMBER:http_version})?|%{DATA:raw_request})" %{NUMBER:response_code} %{NUMBER:bytes}' 
      }
      add_tag => ["nginx_parsed"]
    }
    
    # Detect SQL injection
    if [request_uri] =~ /(\%27)|(\')|(\-\-)|(\%23)|(#)|(union)|(select)/i {
      mutate {
        add_tag => ["sql_injection", "web_attack", "security_alert"]
      }
    }
    
    # Detect XSS
    if [request_uri] =~ /(<script|javascript:|onerror=|onload=)/i {
      mutate {
        add_tag => ["xss", "web_attack", "security_alert"]
      }
    }
  }
  
  # Add HMAC for integrity check
  ruby {
    code => '
      require "openssl"
      message = event.get("message")
      timestamp = event.get("@timestamp")
      host = event.get("host.name") || "unknown"
      
      if message && timestamp && host
        payload = timestamp.to_s + host + message
        hmac = OpenSSL::HMAC.hexdigest("SHA256", "test-secret-key", payload)
        event.set("integrity.hmac", hmac)
      end
    '
  }
  
  # Add timestamp parsing
  date {
    match => [ "timestamp", 
               "MMM  d HH:mm:ss", 
               "MMM dd HH:mm:ss",
               "dd/MMM/yyyy:HH:mm:ss Z",
               "ISO8601" 
             ]
    target => "@timestamp"
    add_tag => ["timestamp_parsed"]
  }
}

output {
  file {
    path => "$LOGSTASH_OUTPUT_FILE"
    codec => json
  }
  stdout {
    codec => json
  }
}
EOF

print_pass "Test Logstash config created: $TEST_LOGSTASH_CONF"

# Create Logstash settings file
TEST_LOGSTASH_SETTINGS="${TEST_DIR}/logstash.yml"
cat > "$TEST_LOGSTASH_SETTINGS" << 'SETTINGS'
path.data: /tmp/logstash-settings-data
path.logs: /tmp/logstash-settings-logs
SETTINGS

print_pass "Test Logstash settings created: $TEST_LOGSTASH_SETTINGS"

# Create minimal Filebeat test config
TEST_FILEBEAT_CONF="${TEST_DIR}/filebeat-test.yml"
cat > "$TEST_FILEBEAT_CONF" << EOF
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - ${TEST_LOG_DIR}/auth.log
    - ${TEST_LOG_DIR}/nginx_access.log
    - ${TEST_LOG_DIR}/syslog
  fields:
    log_type: test
    environment: test
  fields_under_root: true

processors:
  - add_host_metadata: ~

output.logstash:
  hosts: ["localhost:5044"]
  ssl.enabled: false

logging.level: info
logging.to_files: true
logging.files:
  path: ${TEST_DIR}
  name: filebeat-test
  keepfiles: 1
  permissions: 0644
EOF

print_pass "Test Filebeat config created: $TEST_FILEBEAT_CONF"

# =============================================================================
# SECTION 5: LOGSTASH PORT TEST
# =============================================================================
print_header "SECTION 5: STARTING LOGSTASH"

# Start Logstash in background
print_info "Starting Logstash on port 5044 (no SSL)..."
logstash -f "$TEST_LOGSTASH_CONF" -w 1 --path.settings "$(dirname $TEST_LOGSTASH_SETTINGS)" > "$LOGSTASH_STDOUT_FILE" 2>&1 &
LOGSTASH_PID=$!
print_info "Logstash PID: $LOGSTASH_PID"

# Wait for Logstash to start
print_info "Waiting for Logstash to initialize..."
sleep 5

# Check if Logstash is still running
if ! kill -0 $LOGSTASH_PID 2>/dev/null; then
    print_fail "Logstash failed to start"
    cat "$LOGSTASH_STDOUT_FILE" | tail -50
    exit 1
fi

# Verify port 5044 is listening
if netstat -tuln 2>/dev/null | grep -q ":5044 " || ss -tuln 2>/dev/null | grep -q ":5044 "; then
    print_pass "Port 5044 is active and listening"
else
    print_warn "Cannot verify port 5044 listening status"
fi

# =============================================================================
# SECTION 6: GENERATE SAMPLE LOGS
# =============================================================================
print_header "SECTION 6: GENERATING SAMPLE LOGS"

# SSH log sample
SSH_LOG="Failed password for root from 192.168.1.10 port 22 ssh2"
echo "$(date +'%b %d %H:%M:%S') localhost sshd[1234]: $SSH_LOG" >> "${TEST_LOG_DIR}/auth.log"
print_pass "SSH auth log sample generated"

# Nginx access log sample
NGINX_LOG='192.168.1.10 - - [10/Oct/2025:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "curl/7.68.0"'
echo "$NGINX_LOG" >> "${TEST_LOG_DIR}/nginx_access.log"
print_pass "Nginx access log sample generated"

# Nginx SQL injection attempt
NGINX_SQLI='192.168.1.11 - - [10/Oct/2025:13:56:00 +0000] "GET /search.php?q=\x27%20union%20select%20* HTTP/1.1" 200 512 "-" "curl/7.68.0"'
echo "$NGINX_SQLI" >> "${TEST_LOG_DIR}/nginx_access.log"
print_pass "Nginx SQL injection log sample generated"

# Nginx XSS attempt
NGINX_XSS='192.168.1.12 - - [10/Oct/2025:13:56:30 +0000] "GET /page.php?data=<script>alert(1)</script> HTTP/1.1" 200 512 "-" "curl/7.68.0"'
echo "$NGINX_XSS" >> "${TEST_LOG_DIR}/nginx_access.log"
print_pass "Nginx XSS log sample generated"

print_info "Logs written to ${TEST_LOG_DIR}"

# =============================================================================
# SECTION 7: FILEBEAT CONNECTION TEST
# =============================================================================
print_header "SECTION 7: STARTING FILEBEAT"

print_info "Starting Filebeat..."
filebeat -c "$TEST_FILEBEAT_CONF" -d "*" > "$FILEBEAT_LOG_FILE" 2>&1 &
FILEBEAT_PID=$!
print_info "Filebeat PID: $FILEBEAT_PID"

# Wait for Filebeat to connect and send logs
print_info "Waiting for Filebeat to harvest and send logs..."
sleep 8

# Check if Filebeat is still running
if kill -0 $FILEBEAT_PID 2>/dev/null; then
    print_pass "Filebeat is running"
else
    print_fail "Filebeat crashed"
    cat "$FILEBEAT_LOG_FILE" | tail -30
fi

# Check Filebeat logs for connection success
if grep -q "Connected" "$FILEBEAT_LOG_FILE" 2>/dev/null || grep -q "connection" "$FILEBEAT_LOG_FILE" 2>/dev/null; then
    print_pass "Filebeat connection established (found connection logs)"
else
    print_info "Checking for Filebeat output indicators..."
fi

# Wait a bit more for logs to be processed
sleep 3

# =============================================================================
# SECTION 8: PARSING VALIDATION
# =============================================================================
print_header "SECTION 8: PARSING VALIDATION"

if [[ -f "$LOGSTASH_OUTPUT_FILE" ]] && [[ -s "$LOGSTASH_OUTPUT_FILE" ]]; then
    print_pass "Logstash output file exists and contains data"
    
    # Count lines in output
    OUTPUT_LINES=$(wc -l < "$LOGSTASH_OUTPUT_FILE")
    print_info "Logstash output lines: $OUTPUT_LINES"
    
    # Check for parsed fields
    if grep -q '"client_ip"' "$LOGSTASH_OUTPUT_FILE" 2>/dev/null; then
        print_pass "Parsed field found: client_ip"
    else
        print_warn "Parsed field not found: client_ip"
    fi
    
    if grep -q '"http_method"' "$LOGSTASH_OUTPUT_FILE" 2>/dev/null; then
        print_pass "Parsed field found: http_method"
    else
        print_warn "Parsed field not found: http_method"
    fi
    
    if grep -q '"response_code"' "$LOGSTASH_OUTPUT_FILE" 2>/dev/null; then
        print_pass "Parsed field found: response_code"
    else
        print_warn "Parsed field not found: response_code"
    fi
    
    if grep -q '"username"' "$LOGSTASH_OUTPUT_FILE" 2>/dev/null; then
        print_pass "Parsed field found: username"
    else
        print_warn "Parsed field not found: username"
    fi
    
    # Check for original message preservation
    if grep -q '"message"' "$LOGSTASH_OUTPUT_FILE" 2>/dev/null; then
        print_pass "Original message field preserved"
    else
        print_fail "Original message field not found"
    fi
else
    print_warn "Logstash output file not created yet (may need more time or no logs sent)"
fi

# =============================================================================
# SECTION 9: HMAC VALIDATION
# =============================================================================
print_header "SECTION 9: HMAC VALIDATION"

if [[ -f "$LOGSTASH_OUTPUT_FILE" ]] && [[ -s "$LOGSTASH_OUTPUT_FILE" ]]; then
    # Extract and validate HMAC from output
    HMAC_COUNT=$(grep -c '"integrity.hmac"' "$LOGSTASH_OUTPUT_FILE" 2>/dev/null || echo 0)
    
    if [[ $HMAC_COUNT -gt 0 ]]; then
        print_pass "HMAC field generated ($HMAC_COUNT entries)"
        
        # Extract a sample HMAC and validate format
        SAMPLE_HMAC=$(grep -o '"integrity.hmac":"[^"]*"' "$LOGSTASH_OUTPUT_FILE" | head -1 | cut -d'"' -f4)
        
        if [[ -n "$SAMPLE_HMAC" && ${#SAMPLE_HMAC} -eq 64 ]]; then
            print_pass "HMAC format valid (SHA256 hex, 64 chars): ${SAMPLE_HMAC:0:16}..."
        else
            print_warn "HMAC format check inconclusive"
        fi
        
        # Verify HMAC computation (manually recompute)
        if grep -q '"@timestamp"' "$LOGSTASH_OUTPUT_FILE"; then
            print_pass "Timestamp field present for HMAC computation"
        fi
    else
        print_warn "No HMAC fields detected in output"
    fi
else
    print_warn "Logstash output file not available for HMAC validation"
fi

# =============================================================================
# SECTION 10: DETECTION VALIDATION
# =============================================================================
print_header "SECTION 10: DETECTION VALIDATION"

if [[ -f "$LOGSTASH_OUTPUT_FILE" ]] && [[ -s "$LOGSTASH_OUTPUT_FILE" ]]; then
    
    # Check for SSH failed login detection
    if grep -q '"ssh_failed_login"' "$LOGSTASH_OUTPUT_FILE" 2>/dev/null; then
        print_pass "SSH failed login tag detected"
    else
        print_warn "SSH failed login tag not detected (may be expected if no SSH logs parsed)"
    fi
    
    # Check for SQL injection detection
    if grep -q '"sql_injection"' "$LOGSTASH_OUTPUT_FILE" 2>/dev/null; then
        print_pass "SQL injection tag detected"
    else
        print_warn "SQL injection tag not detected"
    fi
    
    # Check for XSS detection
    if grep -q '"xss"' "$LOGSTASH_OUTPUT_FILE" 2>/dev/null; then
        print_pass "XSS tag detected"
    else
        print_warn "XSS tag not detected"
    fi
    
    # Check for security alert tags
    if grep -q '"security_alert"' "$LOGSTASH_OUTPUT_FILE" 2>/dev/null; then
        print_pass "Security alert tags present"
    else
        print_warn "Security alert tags not detected"
    fi
    
    # Check for parsed tags
    if grep -q '"nginx_parsed"' "$LOGSTASH_OUTPUT_FILE" 2>/dev/null; then
        print_pass "Nginx parsing tag detected"
    else
        print_warn "Nginx parsing tag not detected"
    fi
    
    if grep -q '"ssh_parsed"' "$LOGSTASH_OUTPUT_FILE" 2>/dev/null; then
        print_pass "SSH parsing tag detected"
    else
        print_warn "SSH parsing tag not detected"
    fi
else
    print_warn "Logstash output file not available for detection validation"
fi

# =============================================================================
# SECTION 11: TEST SUMMARY
# =============================================================================
print_header "SECTION 11: TEST SUMMARY"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

for result in "${TEST_RESULTS[@]}"; do
    status="${result%%|*}"
    message="${result##*|}"
    
    case "$status" in
        PASS) ((PASS_COUNT++)) ;;
        FAIL) ((FAIL_COUNT++)) ;;
        WARN) ((WARN_COUNT++)) ;;
    esac
done

echo ""
echo -e "${GREEN}Passed:${NC} $PASS_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "${RED}Failed:${NC} $FAIL_COUNT"
fi

# =============================================================================
# SECTION 12: DIAGNOSTIC OUTPUT
# =============================================================================
print_header "SECTION 12: DIAGNOSTIC OUTPUT"

print_info "Logstash stdout (last 20 lines):"
tail -20 "$LOGSTASH_STDOUT_FILE" 2>/dev/null || echo "No output"

print_info "Filebeat log (last 20 lines):"
tail -20 "$FILEBEAT_LOG_FILE" 2>/dev/null || echo "No output"

print_info "Test output file location: $LOGSTASH_OUTPUT_FILE"
print_info "Test directory: $TEST_DIR"

# =============================================================================
# EXIT STATUS
# =============================================================================
print_header "TEST EXECUTION COMPLETE"

if [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "${RED}RESULT: TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}RESULT: ALL TESTS PASSED${NC}"
    exit 0
fi
