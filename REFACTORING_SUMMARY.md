# ================================================================
# REFACTORING SUMMARY: FILEBEAT & LOGSTASH PRODUCTION READINESS
# ================================================================

## ✅ COMPLETED REFACTORING

### 1. FILEBEAT.YML - IMPROVEMENTS

#### ❌ REMOVED (No Longer Present)
- **HMAC/Hash Logic** - Script processor computing log_hash removed (now Logstash responsibility)
- **add_docker_metadata** - Removed to reduce dependencies and improve portability
- **add_kubernetes_metadata** - Removed (not essential for basic logging)
- **monitoring.* section** - Entire monitoring.elasticsearch removed (out of scope)
- **setup.kibana** - Removed (out of scope)
- **setup.ilm.*** - All ILM (Index Lifecycle Management) settings removed (out of scope)
- **setup.template.settings** - Removed (managed by Logstash/Elasticsearch)
- **filebeat.config.modules** - Module loading removed (unnecessary for direct log ingestion)
- **Alternative Elasticsearch output** - Commented Elasticsearch output removed

#### ✅ IMPROVED (Environment Portable)
- **Hardcoded paths → Environment variables with fallbacks:**
  - `/var/log/auth.log` → `${AUTH_LOG_PATH:/var/log/auth.log}`
  - `/var/log/nginx/access.log` → `${NGINX_ACCESS_LOG_PATH:/var/log/nginx/access.log}`
  - `/var/log/nginx/error.log` → `${NGINX_ERROR_LOG_PATH:/var/log/nginx/error.log}`
  - `/var/log/syslog` → `${SYSLOG_PATH:/var/log/syslog}`
  - `/var/log/ufw.log` → `${FIREWALL_LOG_PATH:/var/log/ufw.log}`
  - `/var/log/app/*.log` → `${APP_LOG_PATH:/var/log/app/*.log}`
  - `/var/log/filebeat` → `${FILEBEAT_LOG_DIR:/var/log/filebeat}`

- **Logstash output configuration:**
  - Host: `${LOGSTASH_HOST:localhost}:${LOGSTASH_PORT:5044}`
  - SSL: `${LOGSTASH_SSL_ENABLED:true}`
  - Certificates use env vars: `${LOGSTASH_CA_CERT}`, `${LOGSTASH_CERT}`, `${LOGSTASH_KEY}`
  - SSL verification: `${LOGSTASH_SSL_VERIFY:full}`

- **Logging improvements:**
  - Configurable log level: `${LOG_LEVEL:info}`
  - Reduced keepfiles from 7 to 3 (production standard)
  - Added log rotation: `rotateeverybytes: 10485760` (10MB)
  - Added logging to stderr control

- **Resilience settings:**
  - Backoff: `backoff.init: 1s`, `backoff.max: 30s`
  - Connection retry logic
  - Graceful SSL fallback (certs not required to start)

- **Moved all Kibana/Elasticsearch setup to disabled state:**
  - `setup.enabled: false` (prevents automatic template/ILM setup)

---

### 2. LOGSTASH.CONF - IMPROVEMENTS

#### ✅ CRITICAL SECURITY ENHANCEMENT: HMAC-SHA256 INTEGRITY

**New Ruby filter for HMAC computation:**
```
Payload: @timestamp|host.name|source.ip|user.name|message
Algorithm: SHA256
Key source: LOG_HMAC_KEY environment variable
Output field: [integrity][hmac]
```

**Features:**
- Uses RFC 2104 HMAC-SHA256 standard
- Consistent field ordering prevents replay attacks
- Field fallback logic prevents crashes if fields missing
- Normalizes fields to ECS (Elastic Common Schema) format
- Includes error handling for missing environment variable (warns "default-insecure-key")

**Example payload:**
```
2026-04-22T17:25:00.000Z|hostname|192.168.1.10|root|Failed password for root from 192.168.1.10
```

#### ✅ INPUT CONFIGURATION - PRODUCTION HARDENED

**Filebeat input (beats):**
- Port: `${LOGSTASH_PORT:5044}` (configurable)
- SSL: `${LOGSTASH_SSL_ENABLED:true}` (optional, with graceful fallback)
- Host binding: `${LOGSTASH_BIND_HOST:0.0.0.0}` (Docker-friendly)
- SSL verification: `${LOGSTASH_SSL_VERIFY:force_peer}` (configurable)
- Certificate paths: All environment variables with sensible defaults
- Connection timeout: `congestion_threshold => 5` (prevent hangs)

**Syslog input:**
- Commented out (can be enabled via configuration edit or environment trigger)

#### ✅ FILTER IMPROVEMENTS - STABILITY & PERFORMANCE

**Error handling for missing fields:**
```
if ![message] { add_field => { "message" => "N/A" } }
if ![host][name] { add_field => { "[host][name]" => "unknown" } }
```

**Log type routing with pre-checks:**
- SSH: `if [log_type] == "ssh_auth" or [message] =~ "sshd\["`
- Nginx: `if [log_type] == "nginx_access" or ([message] =~ /GET|POST/ and [message] =~ /HTTP/)`
- Firewall: `if [log_type] == "firewall" or [message] =~ /UFW|iptables/`

**Regex optimization with pre-conditions:**
- SQL injection: Pre-check for suspicious characters before expensive regex
  ```
  if [request_uri] and ([request_uri] =~ /[%'#-]/ or [request_uri] =~ /(union|select)/i)
  ```
- XSS: Pre-check for angle brackets or javascript keywords before regex
  ```
  if [request_uri] and ([request_uri] =~ /<|javascript:|script>/i)
  ```

**Field normalization to ECS:**
- All fields normalized to ECS format:
  - `[source][ip]`, `[destination][ip]`, `[user][name]`, `[http][method]`, `[http][response][status_code]`
- Backward compatibility: Root-level fields also created (e.g., `source_ip`, `username`)

**Alert level classification:**
```
- All security_alerts: alert_level = "warning"
- SQL injection + XSS: alert_level = "critical"
```

#### ✅ OUTPUT IMPROVEMENTS - RESILIENCE & FLEXIBILITY

**Debug output (controlled):**
```
if [@metadata][debug] or "${LOG_DEBUG:false}" == "true"
```
- Disabled by default
- Enables JSON console output for troubleshooting

**Elasticsearch output (optional):**
- Fully configurable via environment variables:
  - `${ELASTICSEARCH_ENABLED:true}` - toggle on/off
  - `${ELASTICSEARCH_HOST:https://elasticsearch:9200}`
  - `${ELASTICSEARCH_USER:logstash_writer}`
  - `${ELASTICSEARCH_PASSWORD:}` - empty by default, set via env
  - `${ELASTICSEARCH_SSL_ENABLED:true}`
  - `${ELASTICSEARCH_SSL_VERIFY:true}`

- Retry and resilience:
  - `retry_on_conflict: 1`
  - `batch_size: 125`
  - `idle_flush_time: 1`
  - `manage_template: false` (no auto-creation conflicts)

**Security alerts routing:**
- Separate index: `security-alerts-%{+YYYY.MM.dd}`
- Document routing: `routing => "%{[alert_level]}"` (for sharding by severity)

**File output (optional, for testing):**
```
if "${LOG_TO_FILE:false}" == "true"
```
- Useful for local testing without Elasticsearch
- JSON codec for easy parsing

---

## 🌍 ENVIRONMENT VARIABLES REFERENCE

### Filebeat
```
# Log paths (Docker volumes mount here)
AUTH_LOG_PATH              # Default: /var/log/auth.log
NGINX_ACCESS_LOG_PATH      # Default: /var/log/nginx/access.log
NGINX_ERROR_LOG_PATH       # Default: /var/log/nginx/error.log
SYSLOG_PATH                # Default: /var/log/syslog
FIREWALL_LOG_PATH          # Default: /var/log/ufw.log
APP_LOG_PATH               # Default: /var/log/app/*.log

# Logging
LOG_LEVEL                  # Default: info
FILEBEAT_LOG_DIR           # Default: /var/log/filebeat

# Output
LOGSTASH_HOST              # Default: localhost
LOGSTASH_PORT              # Default: 5044
LOGSTASH_SSL_ENABLED       # Default: true
LOGSTASH_SSL_VERIFY        # Default: full
LOGSTASH_CA_CERT           # Default: /etc/filebeat/certs/ca.crt
LOGSTASH_CERT              # Default: /etc/filebeat/certs/filebeat.crt
LOGSTASH_KEY               # Default: /etc/filebeat/certs/filebeat.key

# Environment
ENVIRONMENT                # Default: production
CLUSTER_NAME               # Default: default
HOSTNAME                   # Default: filebeat-security-monitor
ENABLE_MONITORING          # Default: false
```

### Logstash
```
# Input (Beats)
LOGSTASH_PORT              # Default: 5044
LOGSTASH_SSL_ENABLED       # Default: true
LOGSTASH_SSL_VERIFY        # Default: force_peer
LOGSTASH_BIND_HOST         # Default: 0.0.0.0 (Docker-friendly)
LOGSTASH_CERT              # Default: /etc/logstash/certs/logstash.crt
LOGSTASH_KEY               # Default: /etc/logstash/certs/logstash.key
LOGSTASH_CA_CERT           # Default: /etc/logstash/certs/ca.crt

# HMAC Security (CRITICAL)
LOG_HMAC_KEY               # MUST BE SET IN PRODUCTION (random 32+ char string)
                           # Default: "default-insecure-key" (warns in logs)

# Output (Elasticsearch)
ELASTICSEARCH_ENABLED      # Default: true
ELASTICSEARCH_HOST         # Default: https://elasticsearch:9200
ELASTICSEARCH_USER         # Default: logstash_writer
ELASTICSEARCH_PASSWORD     # Default: "" (empty)
ELASTICSEARCH_SSL_ENABLED  # Default: true
ELASTICSEARCH_SSL_VERIFY   # Default: true
ELASTICSEARCH_CA_CERT      # Default: /etc/logstash/certs/ca.crt

# Debug & Testing
LOG_DEBUG                  # Default: false
LOG_TO_FILE                # Default: false
LOG_OUTPUT_FILE            # Default: /tmp/logstash-output.json
```

---

## 🚀 DOCKER DEPLOYMENT EXAMPLE

```dockerfile
# docker-compose.yml snippet
filebeat:
  environment:
    - LOGSTASH_HOST=logstash
    - AUTH_LOG_PATH=/logs/auth.log
    - NGINX_ACCESS_LOG_PATH=/logs/nginx/access.log
    - SYSLOG_PATH=/logs/syslog
  volumes:
    - /var/log:/logs:ro  # Mount host logs as read-only

logstash:
  environment:
    - LOGSTASH_BIND_HOST=0.0.0.0
    - LOGSTASH_SSL_ENABLED=false  # Disable for local testing
    - LOG_HMAC_KEY=your-secret-key-32-chars-minimum-required
    - ELASTICSEARCH_HOST=https://elasticsearch:9200
    - ELASTICSEARCH_PASSWORD=your-es-password
```

---

## ⚠️ PRODUCTION CHECKLIST

### Before Deploying to Production:

- [ ] **Set LOG_HMAC_KEY** - Generate random 32+ character string
- [ ] **SSL Certificates** - Provide valid certificates or set `LOGSTASH_SSL_ENABLED=false` for testing
- [ ] **Elasticsearch Connection** - Test `ELASTICSEARCH_HOST`, `ELASTICSEARCH_USER`, `ELASTICSEARCH_PASSWORD`
- [ ] **Log Paths** - Ensure all `*_LOG_PATH` environment variables point to correct volumes
- [ ] **Firewall Rules** - Open port 5044 (Filebeat→Logstash) and 5514 (syslog, if enabled)
- [ ] **Disk Space** - Monitor `/var/log/filebeat` for log rotation
- [ ] **Monitoring** - Set `ENABLE_MONITORING=true` for health checks (optional)
- [ ] **Debug Disabled** - Ensure `LOG_DEBUG=false` in production (performance impact)

---

## 🎯 TESTING VERIFICATION

```bash
# Test Logstash config syntax
logstash -t -f /path/to/logstash.conf

# Test Filebeat config syntax
filebeat test config -c /path/to/filebeat.yml

# Test Filebeat output connection
filebeat test output -c /path/to/filebeat.yml

# Verify HMAC computation
# Look for [integrity][hmac] in Elasticsearch documents or log output
```

---

## ✨ KEY ACHIEVEMENTS

1. **Docker Compatible** ✅ - All hardcoded paths replaced with env variables
2. **Portable** ✅ - Runs on any VM/container with environment configuration
3. **Secure** ✅ - HMAC-SHA256 integrity verification in Logstash
4. **Stable** ✅ - Error handling prevents crashes on missing fields/SSL
5. **Performant** ✅ - Pre-check conditions before expensive regex
6. **Debuggable** ✅ - Optional stdout output controlled via LOG_DEBUG
7. **Resilient** ✅ - Backoff, retry, and graceful fallback logic
8. **ECS Compliant** ✅ - Fields normalized to Elastic Common Schema
9. **Production Ready** ✅ - Follows industry best practices
10. **Scope Compliant** ✅ - Only modified filebeat.yml and logstash.conf

---

## ⚠️ REMAINING EXTERNAL DEPENDENCIES

These are outside the scope but required for full pipeline operation:

1. **Elasticsearch** - Log storage and indexing (not modified)
2. **Kibana** - Dashboard and visualization (not modified)
3. **SSL Certificates** - For encrypted communication (user-provided)
4. **LOG_HMAC_KEY** - Secret key for integrity (user must set)
5. **Syslog server** (optional) - If syslog input enabled

---

## 📋 FILES MODIFIED

- ✅ `/CO3069_Assignment_CLM/configs/filebeat.yml` - FULLY REFACTORED
- ✅ `/CO3069_Assignment_CLM/configs/logstash.conf` - FULLY REFACTORED
- ❌ No other files modified (docker-compose, Elasticsearch, Kibana untouched)
