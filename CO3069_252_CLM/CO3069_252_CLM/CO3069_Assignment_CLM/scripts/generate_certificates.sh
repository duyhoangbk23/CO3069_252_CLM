#!/bin/bash
################################################################################
# TLS Certificate Generation Script
#
# This script generates a complete PKI infrastructure for securing the
# centralized log management system with TLS encryption.
#
# Generated certificates:
# - Root CA certificate
# - Elasticsearch certificate
# - Logstash certificate
# - Kibana certificate
# - Filebeat certificate
#
# Usage: ./generate_certificates.sh
#
# Author: Security Team
# Date: 2026-03-31
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CERT_DIR="./certs"
VALIDITY_DAYS=365
KEY_SIZE=4096
CA_KEY_SIZE=4096

# Certificate details
COUNTRY="VN"
STATE="Ho Chi Minh"
CITY="Ho Chi Minh City"
ORGANIZATION="HCMC University of Technology"
ORG_UNIT="Security Lab"

print_header() {
    echo -e "${BLUE}================================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================================================${NC}"
}

print_step() {
    echo -e "\n${YELLOW}➤${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

################################################################################
# Certificate Generation Functions
################################################################################

generate_ca() {
    print_step "Generating Root Certificate Authority (CA)"
    
    # Generate CA private key
    openssl genrsa -out "$CERT_DIR/ca.key" $CA_KEY_SIZE
    print_success "CA private key generated: ca.key"
    
    # Generate CA certificate
    openssl req -new -x509 -days $((VALIDITY_DAYS * 3)) \
        -key "$CERT_DIR/ca.key" \
        -out "$CERT_DIR/ca.crt" \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORG_UNIT/CN=Log Management Root CA"
    
    print_success "CA certificate generated: ca.crt (valid for $((VALIDITY_DAYS * 3)) days)"
    
    # Display CA certificate details
    echo ""
    openssl x509 -in "$CERT_DIR/ca.crt" -noout -text | grep -A 2 "Subject:"
    openssl x509 -in "$CERT_DIR/ca.crt" -noout -text | grep -A 2 "Validity"
}

generate_component_cert() {
    local component=$1
    local common_name=$2
    local san=$3
    
    print_step "Generating certificate for $component"
    
    # Generate private key
    openssl genrsa -out "$CERT_DIR/${component}.key" $KEY_SIZE
    print_success "${component}.key generated"
    
    # Create certificate signing request (CSR)
    openssl req -new \
        -key "$CERT_DIR/${component}.key" \
        -out "$CERT_DIR/${component}.csr" \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORG_UNIT/CN=$common_name"
    
    print_success "${component}.csr generated"
    
    # Create SAN configuration file
    cat > "$CERT_DIR/${component}_san.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORGANIZATION
OU = $ORG_UNIT
CN = $common_name

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $common_name
DNS.2 = localhost
DNS.3 = ${component}
$san
EOF
    
    # Sign certificate with CA
    openssl x509 -req -days $VALIDITY_DAYS \
        -in "$CERT_DIR/${component}.csr" \
        -CA "$CERT_DIR/ca.crt" \
        -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial \
        -out "$CERT_DIR/${component}.crt" \
        -extensions v3_req \
        -extfile "$CERT_DIR/${component}_san.cnf"
    
    print_success "${component}.crt generated and signed (valid for $VALIDITY_DAYS days)"
    
    # Verify certificate
    openssl verify -CAfile "$CERT_DIR/ca.crt" "$CERT_DIR/${component}.crt" > /dev/null 2>&1
    print_success "Certificate verification passed"
    
    # Create PKCS12 keystore (for Java applications)
    openssl pkcs12 -export \
        -in "$CERT_DIR/${component}.crt" \
        -inkey "$CERT_DIR/${component}.key" \
        -out "$CERT_DIR/${component}.p12" \
        -name "$component" \
        -CAfile "$CERT_DIR/ca.crt" \
        -caname "root" \
        -password pass:changeit
    
    print_success "${component}.p12 keystore generated (password: changeit)"
    
    # Clean up CSR and SAN config
    rm -f "$CERT_DIR/${component}.csr" "$CERT_DIR/${component}_san.cnf"
}

create_truststore() {
    print_step "Creating Java truststore"
    
    # Convert CA certificate to Java truststore
    keytool -import -trustcacerts -noprompt \
        -alias ca \
        -file "$CERT_DIR/ca.crt" \
        -keystore "$CERT_DIR/truststore.jks" \
        -storepass changeit 2>/dev/null
    
    print_success "truststore.jks created (password: changeit)"
}

set_permissions() {
    print_step "Setting secure file permissions"
    
    # Private keys should be readable only by owner
    chmod 600 "$CERT_DIR"/*.key
    print_success "Private keys protected (600)"
    
    # Certificates can be world-readable
    chmod 644 "$CERT_DIR"/*.crt
    print_success "Certificates readable (644)"
    
    # PKCS12 files should be protected
    chmod 600 "$CERT_DIR"/*.p12
    print_success "PKCS12 keystores protected (600)"
    
    # JKS truststore readable by group
    chmod 640 "$CERT_DIR"/*.jks 2>/dev/null || true
    print_success "Java truststore protected (640)"
}

generate_readme() {
    print_step "Generating README"
    
    cat > "$CERT_DIR/README.md" <<'EOF'
# TLS Certificates for Centralized Log Management

## Certificate Structure

```
ca.crt                  # Root Certificate Authority
ca.key                  # CA Private Key (KEEP SECRET!)

elasticsearch.crt       # Elasticsearch Server Certificate
elasticsearch.key       # Elasticsearch Private Key
elasticsearch.p12       # Elasticsearch PKCS12 Keystore

logstash.crt           # Logstash Server Certificate
logstash.key           # Logstash Private Key
logstash.p12           # Logstash PKCS12 Keystore

kibana.crt             # Kibana Server Certificate
kibana.key             # Kibana Private Key
kibana.p12             # Kibana PKCS12 Keystore

filebeat.crt           # Filebeat Client Certificate
filebeat.key           # Filebeat Private Key
filebeat.p12           # Filebeat PKCS12 Keystore

truststore.jks         # Java Truststore (contains CA)
```

## Usage Examples

### Elasticsearch Configuration

```yaml
xpack.security.http.ssl:
  enabled: true
  key: certs/elasticsearch.key
  certificate: certs/elasticsearch.crt
  certificate_authorities: certs/ca.crt
```

### Logstash Configuration

```ruby
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/logstash/certs/logstash.crt"
    ssl_key => "/etc/logstash/certs/logstash.key"
    ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
  }
}

output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    ssl => true
    cacert => "/etc/logstash/certs/ca.crt"
  }
}
```

### Filebeat Configuration

```yaml
output.logstash:
  hosts: ["logstash:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["/etc/filebeat/certs/ca.crt"]
  ssl.certificate: "/etc/filebeat/certs/filebeat.crt"
  ssl.key: "/etc/filebeat/certs/filebeat.key"
```

### Kibana Configuration

```yaml
server.ssl.enabled: true
server.ssl.certificate: /etc/kibana/certs/kibana.crt
server.ssl.key: /etc/kibana/certs/kibana.key

elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca.crt"]
```

## Certificate Verification

### Verify certificate chain
```bash
openssl verify -CAfile ca.crt elasticsearch.crt
```

### View certificate details
```bash
openssl x509 -in elasticsearch.crt -text -noout
```

### Test TLS connection
```bash
openssl s_client -connect localhost:9200 -CAfile ca.crt
```

### Check certificate expiration
```bash
openssl x509 -in elasticsearch.crt -noout -enddate
```

## Security Notes

⚠️ **IMPORTANT:**
- Keep all `.key` files SECRET and secure
- Never commit private keys to version control
- Use strong file permissions (600 for keys)
- Rotate certificates before expiration
- Use environment-specific certificates (dev/staging/prod)

## Certificate Renewal

Certificates are valid for 365 days. To renew:

```bash
./generate_certificates.sh
```

Then restart all services to load new certificates.

## Troubleshooting

### "certificate verify failed"
- Ensure CA certificate is in the certificate_authorities list
- Check certificate chain: `openssl verify -CAfile ca.crt server.crt`

### "certificate has expired"
- Check expiration: `openssl x509 -in server.crt -noout -enddate`
- Regenerate certificates if expired

### "hostname doesn't match certificate"
- Ensure SAN includes all hostnames/IPs used to access the service
- Check SAN: `openssl x509 -in server.crt -noout -text | grep -A1 "Subject Alternative Name"`
EOF
    
    print_success "README.md created with usage instructions"
}

display_summary() {
    print_header "CERTIFICATE GENERATION SUMMARY"
    
    echo ""
    echo "Certificate Directory: $CERT_DIR"
    echo "Certificate Validity: $VALIDITY_DAYS days"
    echo ""
    echo "Generated Certificates:"
    echo "  ✓ Root CA"
    echo "  ✓ Elasticsearch"
    echo "  ✓ Logstash"
    echo "  ✓ Kibana"
    echo "  ✓ Filebeat"
    echo ""
    echo "Certificate Expiration Dates:"
    echo ""
    
    for cert in ca elasticsearch logstash kibana filebeat; do
        if [ -f "$CERT_DIR/${cert}.crt" ]; then
            expiry=$(openssl x509 -in "$CERT_DIR/${cert}.crt" -noout -enddate | cut -d= -f2)
            printf "  %-15s: %s\n" "$cert" "$expiry"
        fi
    done
    
    echo ""
    echo -e "${YELLOW}⚠ IMPORTANT SECURITY NOTES:${NC}"
    echo "  1. Keep all .key files secure and never commit to git"
    echo "  2. Use these certificates only in development/testing"
    echo "  3. For production, use certificates from a trusted CA"
    echo "  4. Set up certificate rotation before expiration"
    echo ""
    echo "Next Steps:"
    echo "  1. Copy certificates to their respective service directories"
    echo "  2. Update service configurations to use TLS"
    echo "  3. Test connections with: openssl s_client -connect host:port -CAfile ca.crt"
    echo "  4. Read $CERT_DIR/README.md for configuration examples"
    echo ""
}

################################################################################
# Main Execution
################################################################################

main() {
    print_header "TLS CERTIFICATE GENERATION FOR LOG MANAGEMENT SYSTEM"
    
    # Create certificate directory
    if [ -d "$CERT_DIR" ]; then
        echo -e "${YELLOW}⚠ Certificate directory exists. Backing up...${NC}"
        mv "$CERT_DIR" "${CERT_DIR}.backup.$(date +%Y%m%d-%H%M%S)"
        print_success "Backup created"
    fi
    
    mkdir -p "$CERT_DIR"
    print_success "Created certificate directory: $CERT_DIR"
    
    # Generate Root CA
    generate_ca
    
    # Generate component certificates
    generate_component_cert "elasticsearch" "elasticsearch.example.com" "IP.1 = 127.0.0.1"
    generate_component_cert "logstash" "logstash.example.com" "IP.1 = 127.0.0.1"
    generate_component_cert "kibana" "kibana.example.com" "IP.1 = 127.0.0.1"
    generate_component_cert "filebeat" "filebeat.example.com" "IP.1 = 127.0.0.1"
    
    # Create Java truststore
    create_truststore
    
    # Set secure permissions
    set_permissions
    
    # Generate README
    generate_readme
    
    # Display summary
    display_summary
    
    print_success "Certificate generation completed successfully!"
}

# Check for required tools
for tool in openssl keytool; do
    if ! command -v $tool &> /dev/null; then
        print_error "$tool is required but not installed"
        exit 1
    fi
done

# Run main function
main "$@"
