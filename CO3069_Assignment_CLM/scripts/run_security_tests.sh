#!/bin/bash
################################################################################
# Automated Security Testing Script
# 
# This script performs automated security testing on the centralized log
# management system by simulating various attack scenarios and verifying
# detection capabilities.
#
# Usage: ./run_security_tests.sh [options]
#
# Author: Security Team
# Date: 2026-03-31
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TARGET_HOST="${TARGET_HOST:-localhost}"
ELASTICSEARCH_HOST="${ELASTICSEARCH_HOST:-localhost:9200}"
KIBANA_HOST="${KIBANA_HOST:-localhost:5601}"
TEST_RESULTS_DIR="${TEST_RESULTS_DIR:-./test-results}"
WAIT_TIME=30  # Seconds to wait for logs to be indexed

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "${BLUE}================================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================================================${NC}"
}

print_test() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "\n${YELLOW}[TEST $TOTAL_TESTS]${NC} $1"
}

print_success() {
    PASSED_TESTS=$((PASSED_TESTS + 1))
    echo -e "${GREEN}✓ PASS:${NC} $1"
}

print_failure() {
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo -e "${RED}✗ FAIL:${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ INFO:${NC} $1"
}

wait_for_indexing() {
    echo -e "${YELLOW}⏳ Waiting ${WAIT_TIME}s for logs to be indexed...${NC}"
    sleep $WAIT_TIME
}

check_elasticsearch() {
    print_info "Checking Elasticsearch connectivity..."
    if curl -s "$ELASTICSEARCH_HOST/_cluster/health" > /dev/null 2>&1; then
        print_success "Elasticsearch is reachable"
        return 0
    else
        print_failure "Cannot connect to Elasticsearch at $ELASTICSEARCH_HOST"
        return 1
    fi
}

query_logs() {
    local query="$1"
    local index="${2:-logs-*}"
    
    curl -s -X GET "$ELASTICSEARCH_HOST/$index/_search" \
        -H 'Content-Type: application/json' \
        -d "$query" | jq '.hits.total.value'
}

################################################################################
# Test Functions
################################################################################

test_ssh_bruteforce() {
    print_test "SSH Brute-Force Attack Detection"
    
    print_info "Simulating SSH brute-force attack..."
    
    # Simulate multiple failed SSH attempts
    for i in {1..10}; do
        # Log fake failed SSH attempt to syslog
        logger -t sshd -p auth.info "Failed password for invalid user testuser$i from 192.168.100.50 port $((50000 + i)) ssh2"
        sleep 0.5
    done
    
    wait_for_indexing
    
    # Query for SSH failed login events
    query='{
        "query": {
            "bool": {
                "must": [
                    { "match": { "tags": "ssh_failed_login" }},
                    { "match": { "source_ip": "192.168.100.50" }}
                ]
            }
        }
    }'
    
    result=$(query_logs "$query")
    
    if [ "$result" -ge 5 ]; then
        print_success "Detected $result failed SSH attempts (threshold: 5)"
        
        # Check if alert was triggered
        alert_query='{
            "query": {
                "bool": {
                    "must": [
                        { "match": { "rule_name": "SSH Brute Force Attack Detection" }},
                        { "range": { "@timestamp": { "gte": "now-2m" }}}
                    ]
                }
            }
        }'
        
        alert_count=$(query_logs "$alert_query" "security-alerts-*")
        
        if [ "$alert_count" -ge 1 ]; then
            print_success "Alert triggered successfully"
        else
            print_failure "Alert was not triggered"
        fi
    else
        print_failure "Only detected $result events (expected: >= 5)"
    fi
}

test_port_scanning() {
    print_test "Port Scanning Detection"
    
    print_info "Simulating port scan..."
    
    # Simulate firewall logs for port scanning
    for port in {20..50}; do
        logger -t kernel "[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=$port"
        sleep 0.2
    done
    
    wait_for_indexing
    
    # Query for blocked connections
    query='{
        "query": {
            "bool": {
                "must": [
                    { "match": { "tags": "blocked_connection" }},
                    { "match": { "source_ip": "203.0.113.100" }}
                ]
            }
        }
    }'
    
    result=$(query_logs "$query")
    
    if [ "$result" -ge 20 ]; then
        print_success "Detected $result blocked connections indicating port scan"
    else
        print_failure "Only detected $result events (expected: >= 20)"
    fi
}

test_sql_injection() {
    print_test "SQL Injection Detection"
    
    print_info "Simulating SQL injection attempts..."
    
    # Various SQL injection payloads
    payloads=(
        "' OR '1'='1"
        "admin'--"
        "1' UNION SELECT NULL,username,password FROM users--"
        "'; DROP TABLE users--"
        "1 AND 1=1"
    )
    
    for payload in "${payloads[@]}"; do
        # Simulate web access log entry
        encoded_payload=$(echo "$payload" | jq -sRr @uri)
        logger -t nginx "192.168.100.75 - - [$(date +'%d/%b/%Y:%H:%M:%S %z')] \"GET /search?q=$encoded_payload HTTP/1.1\" 403 234 \"-\" \"Mozilla/5.0\""
        sleep 0.5
    done
    
    wait_for_indexing
    
    # Query for SQL injection attempts
    query='{
        "query": {
            "bool": {
                "must": [
                    { "match": { "tags": "sql_injection" }},
                    { "match": { "client_ip": "192.168.100.75" }}
                ]
            }
        }
    }'
    
    result=$(query_logs "$query")
    
    if [ "$result" -ge 3 ]; then
        print_success "Detected $result SQL injection attempts"
    else
        print_failure "Only detected $result attempts (expected: >= 3)"
    fi
}

test_xss_detection() {
    print_test "Cross-Site Scripting (XSS) Detection"
    
    print_info "Simulating XSS attempts..."
    
    # XSS payloads
    xss_payloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "javascript:alert('XSS')"
        "<iframe src='javascript:alert(1)'></iframe>"
    )
    
    for payload in "${xss_payloads[@]}"; do
        encoded_payload=$(echo "$payload" | jq -sRr @uri)
        logger -t nginx "192.168.100.80 - - [$(date +'%d/%b/%Y:%H:%M:%S %z')] \"GET /comment?text=$encoded_payload HTTP/1.1\" 400 156 \"-\" \"curl/7.68.0\""
        sleep 0.5
    done
    
    wait_for_indexing
    
    # Query for XSS attempts
    query='{
        "query": {
            "bool": {
                "must": [
                    { "match": { "tags": "xss_attempt" }},
                    { "match": { "client_ip": "192.168.100.80" }}
                ]
            }
        }
    }'
    
    result=$(query_logs "$query")
    
    if [ "$result" -ge 2 ]; then
        print_success "Detected $result XSS attempts"
    else
        print_failure "Only detected $result attempts (expected: >= 2)"
    fi
}

test_log_integrity() {
    print_test "Log Integrity Verification"
    
    print_info "Verifying log integrity with HMAC signatures..."
    
    # Run the integrity verification script
    if python3 verify_log_integrity.py --elasticsearch-host "$ELASTICSEARCH_HOST" --index "logs-*" --max-logs 100 > /dev/null 2>&1; then
        print_success "Log integrity verification passed"
    else
        print_failure "Log integrity verification failed"
    fi
}

test_tls_configuration() {
    print_test "TLS/SSL Configuration Security"
    
    print_info "Testing TLS configuration..."
    
    # Test Elasticsearch TLS
    if echo | openssl s_client -connect ${ELASTICSEARCH_HOST//:/ } -tls1_3 2>&1 | grep -q "TLSv1.3"; then
        print_success "Elasticsearch supports TLS 1.3"
    else
        print_failure "Elasticsearch does not support TLS 1.3"
    fi
    
    # Check for weak ciphers
    weak_ciphers=$(echo | openssl s_client -connect ${ELASTICSEARCH_HOST//:/ } -cipher 'DES:RC4:MD5' 2>&1 | grep -c "Cipher")
    
    if [ "$weak_ciphers" -eq 0 ]; then
        print_success "No weak ciphers detected"
    else
        print_failure "Weak ciphers are enabled"
    fi
}

test_authentication() {
    print_test "Authentication and Authorization"
    
    print_info "Testing unauthorized access..."
    
    # Attempt to access Elasticsearch without credentials
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "$ELASTICSEARCH_HOST")
    
    if [ "$http_code" -eq 401 ]; then
        print_success "Unauthorized access correctly denied (401)"
    else
        print_failure "Expected 401, got $http_code"
    fi
}

test_rate_limiting() {
    print_test "Rate Limiting and DoS Protection"
    
    print_info "Testing rate limiting..."
    
    # Simulate rapid requests
    success_count=0
    for i in {1..50}; do
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "$KIBANA_HOST" 2>&1)
        if [ "$http_code" -eq 200 ] || [ "$http_code" -eq 302 ]; then
            success_count=$((success_count + 1))
        fi
        sleep 0.1
    done
    
    if [ "$success_count" -lt 50 ]; then
        print_success "Rate limiting appears to be active (only $success_count/50 requests succeeded)"
    else
        print_failure "No rate limiting detected ($success_count/50 requests succeeded)"
    fi
}

################################################################################
# Performance Tests
################################################################################

test_log_throughput() {
    print_test "Log Ingestion Throughput"
    
    print_info "Testing log ingestion rate..."
    
    start_time=$(date +%s)
    
    # Send 1000 log entries
    for i in {1..1000}; do
        logger -t test-app "Test log entry $i with timestamp $(date -Iseconds)"
    done
    
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    throughput=$((1000 / duration))
    
    print_info "Throughput: $throughput events/second"
    
    if [ "$throughput" -ge 50 ]; then
        print_success "Throughput is acceptable (>= 50 eps)"
    else
        print_failure "Throughput is low (< 50 eps)"
    fi
}

test_query_performance() {
    print_test "Query Performance"
    
    print_info "Testing query response time..."
    
    query='{
        "query": {
            "match_all": {}
        },
        "size": 100
    }'
    
    start_time=$(date +%s%N)
    query_logs "$query" > /dev/null
    end_time=$(date +%s%N)
    
    response_time=$(( (end_time - start_time) / 1000000 ))  # Convert to milliseconds
    
    print_info "Query response time: ${response_time}ms"
    
    if [ "$response_time" -lt 1000 ]; then
        print_success "Query performance is good (< 1000ms)"
    else
        print_failure "Query is slow (>= 1000ms)"
    fi
}

################################################################################
# Generate Report
################################################################################

generate_report() {
    local report_file="$TEST_RESULTS_DIR/security-test-report-$(date +%Y%m%d-%H%M%S).txt"
    
    mkdir -p "$TEST_RESULTS_DIR"
    
    {
        echo "================================================================================"
        echo "                   SECURITY TEST REPORT"
        echo "================================================================================"
        echo ""
        echo "Test Date: $(date)"
        echo "Target Host: $TARGET_HOST"
        echo "Elasticsearch: $ELASTICSEARCH_HOST"
        echo "Kibana: $KIBANA_HOST"
        echo ""
        echo "================================================================================"
        echo "                   TEST RESULTS SUMMARY"
        echo "================================================================================"
        echo ""
        echo "Total Tests:   $TOTAL_TESTS"
        echo "Passed Tests:  $PASSED_TESTS"
        echo "Failed Tests:  $FAILED_TESTS"
        echo ""
        
        if [ "$FAILED_TESTS" -eq 0 ]; then
            echo "Status: ✓ ALL TESTS PASSED"
        else
            echo "Status: ✗ SOME TESTS FAILED"
        fi
        
        echo ""
        echo "Success Rate:  $(( (PASSED_TESTS * 100) / TOTAL_TESTS ))%"
        echo ""
        echo "================================================================================"
    } | tee "$report_file"
    
    print_info "Report saved to: $report_file"
}

################################################################################
# Main Execution
################################################################################

main() {
    print_header "CENTRALIZED LOG MANAGEMENT SECURITY TEST SUITE"
    
    echo ""
    print_info "Starting security tests..."
    print_info "Results will be saved to: $TEST_RESULTS_DIR"
    echo ""
    
    # Pre-flight checks
    if ! check_elasticsearch; then
        echo -e "${RED}Cannot proceed without Elasticsearch connection${NC}"
        exit 1
    fi
    
    # Run all tests
    test_ssh_bruteforce
    test_port_scanning
    test_sql_injection
    test_xss_detection
    test_log_integrity
    test_tls_configuration
    test_authentication
    test_rate_limiting
    test_log_throughput
    test_query_performance
    
    # Generate report
    echo ""
    generate_report
    
    # Exit with appropriate code
    if [ "$FAILED_TESTS" -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"
