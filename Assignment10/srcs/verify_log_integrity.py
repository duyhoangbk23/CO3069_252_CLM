import sys
import hashlib
import hmac
import json
from elasticsearch import Elasticsearch

# Configuration - should match .env and Logstash config
ELASTIC_URL = "https://localhost:9200"
CA_CERT = "certs/ca.crt" # Relative to project root

def verify_document(index, doc_id, hmac_key, elastic_password):
    # Initialize ES client
    es = Elasticsearch(
        ELASTIC_URL,
        ca_certs=CA_CERT,
        basic_auth=("elastic", elastic_password),
        verify_certs=True
    )

    try:
        # Fetch the document
        res = es.get(index=index, id=doc_id)
        doc = res['_source']
        
        # Extract fields exactly as Logstash payload
        # payload = "#{timestamp}|#{hostname}|#{source_ip}|#{username}|#{message}"
        timestamp = doc.get('@timestamp', '')
        hostname  = doc.get('host', {}).get('name', 'unknown')
        source_ip = doc.get('source', {}).get('ip', '')
        username  = doc.get('user', {}).get('name', '')
        message   = doc.get('message', '')

        payload = f"{timestamp}|{hostname}|{source_ip}|{username}|{message}"
        
        # Calculate HMAC
        calculated_hmac = hmac.new(
            hmac_key.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        stored_hmac = doc.get('integrity', {}).get('hmac')

        print("-" * 40)
        print(f"Document ID: {doc_id}")
        print(f"Payload:     {payload}")
        print(f"Stored HMAC: {stored_hmac}")
        print(f"Calc HMAC:   {calculated_hmac}")
        print("-" * 40)

        if calculated_hmac == stored_hmac:
            print("SUCCESS: Integrity Verified! ✅")
        else:
            print("FAILURE: Integrity Check Failed! ❌ (Document may have been tampered with)")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python verify_log_integrity.py <index> <doc_id> <hmac_key> <elastic_password>")
        sys.exit(1)

    index = sys.argv[1]
    doc_id = sys.argv[2]
    hmac_key = sys.argv[3]
    elastic_password = sys.argv[4]

    verify_document(index, doc_id, hmac_key, elastic_password)
