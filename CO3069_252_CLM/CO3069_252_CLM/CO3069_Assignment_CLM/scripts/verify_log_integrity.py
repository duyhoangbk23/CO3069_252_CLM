#!/usr/bin/env python3
"""
Log Integrity Verification Script
==================================
This script verifies the integrity of log entries using HMAC-SHA256 signatures.

Usage:
    python3 verify_log_integrity.py --log-file /path/to/logs.json
    python3 verify_log_integrity.py --elasticsearch-host localhost:9200 --index logs-*

Author: Security Team
Date: 2026-03-31
"""

import hmac
import hashlib
import json
import argparse
import sys
from datetime import datetime
from typing import Dict, List, Tuple
from elasticsearch import Elasticsearch
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# Secret key for HMAC (In production, load from secure vault)
SECRET_KEY = b'your-secret-key-here-change-in-production'


def sign_log_entry(log_entry: Dict) -> str:
    """
    Generate HMAC-SHA256 signature for a log entry.
    
    Args:
        log_entry: Dictionary containing log data
        
    Returns:
        Hexadecimal signature string
    """
    # Create a copy without signature field
    log_copy = {k: v for k, v in log_entry.items() if k != 'signature'}
    
    # Serialize to JSON with sorted keys for consistency
    log_json = json.dumps(log_copy, sort_keys=True)
    
    # Generate HMAC signature
    signature = hmac.new(
        SECRET_KEY,
        log_json.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return signature


def verify_log_entry(log_entry: Dict) -> Tuple[bool, str]:
    """
    Verify the integrity of a log entry.
    
    Args:
        log_entry: Dictionary containing log data with signature
        
    Returns:
        Tuple of (is_valid, message)
    """
    if 'signature' not in log_entry:
        return False, "No signature found"
    
    stored_signature = log_entry.get('signature')
    
    # Calculate expected signature
    expected_signature = sign_log_entry(log_entry)
    
    # Compare signatures using constant-time comparison
    is_valid = hmac.compare_digest(stored_signature, expected_signature)
    
    if is_valid:
        return True, "Signature valid"
    else:
        return False, "Signature mismatch - log may have been tampered with"


def verify_logs_from_file(file_path: str) -> None:
    """
    Verify log integrity from a JSON file.
    
    Args:
        file_path: Path to JSON log file
    """
    print(f"{Fore.CYAN}Reading logs from: {file_path}{Style.RESET_ALL}\n")
    
    try:
        with open(file_path, 'r') as f:
            logs = [json.loads(line) for line in f]
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found: {file_path}{Style.RESET_ALL}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}Error: Invalid JSON in file: {e}{Style.RESET_ALL}")
        sys.exit(1)
    
    verify_logs(logs)


def verify_logs_from_elasticsearch(host: str, index: str, max_logs: int = 1000) -> None:
    """
    Verify log integrity from Elasticsearch.
    
    Args:
        host: Elasticsearch host
        index: Index pattern to search
        max_logs: Maximum number of logs to verify
    """
    print(f"{Fore.CYAN}Connecting to Elasticsearch: {host}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Querying index: {index}{Style.RESET_ALL}\n")
    
    try:
        es = Elasticsearch([host])
        
        # Query logs with signatures
        query = {
            "query": {
                "exists": {
                    "field": "signature"
                }
            },
            "size": max_logs,
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ]
        }
        
        result = es.search(index=index, body=query)
        logs = [hit['_source'] for hit in result['hits']['hits']]
        
        print(f"{Fore.GREEN}Found {len(logs)} logs with signatures{Style.RESET_ALL}\n")
        verify_logs(logs)
        
    except Exception as e:
        print(f"{Fore.RED}Error connecting to Elasticsearch: {e}{Style.RESET_ALL}")
        sys.exit(1)


def verify_logs(logs: List[Dict]) -> None:
    """
    Verify a list of log entries and print results.
    
    Args:
        logs: List of log entry dictionaries
    """
    valid_count = 0
    invalid_count = 0
    missing_signature = 0
    
    print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'LOG INTEGRITY VERIFICATION REPORT':^80}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
    
    for i, log_entry in enumerate(logs, 1):
        timestamp = log_entry.get('@timestamp', 'Unknown')
        log_id = log_entry.get('log_id', f'log-{i}')
        
        if 'signature' not in log_entry:
            missing_signature += 1
            print(f"{Fore.YELLOW}[{i}/{len(logs)}] {log_id} ({timestamp})")
            print(f"  Status: {Fore.YELLOW}NO SIGNATURE{Style.RESET_ALL}\n")
            continue
        
        is_valid, message = verify_log_entry(log_entry)
        
        if is_valid:
            valid_count += 1
            print(f"{Fore.GREEN}✓ [{i}/{len(logs)}] {log_id} ({timestamp})")
            print(f"  Status: {Fore.GREEN}{message}{Style.RESET_ALL}\n")
        else:
            invalid_count += 1
            print(f"{Fore.RED}✗ [{i}/{len(logs)}] {log_id} ({timestamp})")
            print(f"  Status: {Fore.RED}{message}{Style.RESET_ALL}")
            print(f"  Stored Signature:   {log_entry.get('signature')[:32]}...")
            print(f"  Expected Signature: {sign_log_entry(log_entry)[:32]}...\n")
    
    # Print summary
    print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'SUMMARY':^80}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
    
    print(f"Total Logs Checked:     {len(logs)}")
    print(f"{Fore.GREEN}Valid Signatures:       {valid_count}{Style.RESET_ALL}")
    print(f"{Fore.RED}Invalid Signatures:     {invalid_count}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Missing Signatures:     {missing_signature}{Style.RESET_ALL}")
    
    integrity_percentage = (valid_count / len(logs) * 100) if logs else 0
    print(f"\nIntegrity Score:        {integrity_percentage:.2f}%")
    
    if invalid_count > 0:
        print(f"\n{Fore.RED}⚠ WARNING: {invalid_count} log(s) failed integrity check!{Style.RESET_ALL}")
        print(f"{Fore.RED}  This may indicate log tampering or corruption.{Style.RESET_ALL}")
        print(f"{Fore.RED}  Immediate investigation is recommended.{Style.RESET_ALL}")
        sys.exit(1)
    elif missing_signature > 0:
        print(f"\n{Fore.YELLOW}⚠ WARNING: {missing_signature} log(s) have no signature.{Style.RESET_ALL}")
        sys.exit(0)
    else:
        print(f"\n{Fore.GREEN}✓ All logs passed integrity verification!{Style.RESET_ALL}")
        sys.exit(0)


def generate_integrity_report(logs: List[Dict], output_file: str) -> None:
    """
    Generate a detailed integrity report in JSON format.
    
    Args:
        logs: List of log entries
        output_file: Path to output report file
    """
    report = {
        "report_timestamp": datetime.now().isoformat(),
        "total_logs": len(logs),
        "results": []
    }
    
    for log_entry in logs:
        is_valid, message = verify_log_entry(log_entry)
        report["results"].append({
            "log_id": log_entry.get('log_id', 'unknown'),
            "timestamp": log_entry.get('@timestamp', 'unknown'),
            "is_valid": is_valid,
            "message": message
        })
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n{Fore.GREEN}Report saved to: {output_file}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description='Verify log integrity using HMAC signatures',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify logs from JSON file
  %(prog)s --log-file /var/log/app/logs.json
  
  # Verify logs from Elasticsearch
  %(prog)s --elasticsearch-host localhost:9200 --index logs-2026.03.*
  
  # Generate detailed report
  %(prog)s --log-file logs.json --report integrity-report.json
        """
    )
    
    parser.add_argument(
        '--log-file',
        help='Path to JSON log file'
    )
    
    parser.add_argument(
        '--elasticsearch-host',
        help='Elasticsearch host (e.g., localhost:9200)'
    )
    
    parser.add_argument(
        '--index',
        default='logs-*',
        help='Elasticsearch index pattern (default: logs-*)'
    )
    
    parser.add_argument(
        '--max-logs',
        type=int,
        default=1000,
        help='Maximum number of logs to verify from Elasticsearch (default: 1000)'
    )
    
    parser.add_argument(
        '--report',
        help='Generate detailed JSON report to specified file'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.log_file and not args.elasticsearch_host:
        parser.error('Either --log-file or --elasticsearch-host must be specified')
    
    if args.log_file and args.elasticsearch_host:
        parser.error('Cannot specify both --log-file and --elasticsearch-host')
    
    # Perform verification
    if args.log_file:
        verify_logs_from_file(args.log_file)
    elif args.elasticsearch_host:
        verify_logs_from_elasticsearch(args.elasticsearch_host, args.index, args.max_logs)


if __name__ == '__main__':
    main()
