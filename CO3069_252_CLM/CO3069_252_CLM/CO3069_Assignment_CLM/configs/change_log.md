# Configuration Change Log - Log Pipeline

## [2.0.0] - 2026-04-22

Refactored Filebeat and Logstash configurations for production-readiness, portability, and improved security.

### 🛡️ Security & Integrity (HMAC)
- **Centralized HMAC-SHA256**: Moved all HMAC calculation logic to Logstash to ensure a single source of truth for log integrity.
- **Improved Payload**: standardized the HMAC payload to include `@timestamp`, `host.name`, `source.ip`, `user.name`, and `message` in a deterministic order.
- **Safe Fallbacks**: Added Ruby error handling in Logstash to prevent pipeline crashes if the `LOG_HMAC_KEY` is missing or fields are malformed.

### 🚀 Performance Optimizations
- **Regex Guarding**: Added keyword-based pre-checks for all heavy detection rules (SSH, Nginx, SQL Injection, XSS, Firewall). This prevents expensive regex processing on logs that clearly don't match the criteria.
- **Early Dropping**: Configured Filebeat to drop `DEBUG` level logs at the source to reduce network and processing overhead.

### 🌍 Portability & Docker Compatibility
- **Variable Path Resolution**: Replaced all hardcoded OS paths in `filebeat.yml` with environment variable fallbacks (e.g., `${LOG_DIR:/logs}`).
- **Dual-Path Support**: Added support for both container-standard paths (`/logs/...`) and legacy Linux paths (`/var/log/...`) simultaneously.
- **Dynamic Host Binding**: Logstash and Filebeat now use environment variables for inter-service communication (`LOGSTASH_HOST`, `ELASTICSEARCH_HOST`).

### 🛠️ Stability Improvements
- **Field Normalization**: Implemented initial `mutate` filters in Logstash to ensure mandatory ECS fields exist before being processed.
- **SSL Flexibility**: Removed strict TLS v1.3 enforcement and moved SSL management to environment variables to support a wider range of legacy and modern clients without configuration changes.
- **Fail-safe Logic**: Replaced hardcoded certificate paths with configurable environment variables with graceful fallbacks.

### 🧹 Cleanup & Compliance
- **Scope Stripping**: Removed unnecessary `setup.kibana`, `setup.ilm`, and `monitoring` blocks from Filebeat to reduce noise and potential startup errors.
- **ECS Alignment**: Renamed custom fields to match the **Elastic Common Schema (ECS)** 8.x standard.
- **Debug Support**: Enhanced `stdout` output in Logstash, controllable via the `LOG_DEBUG` environment variable.

---
**Author:** Antigravity DevSecOps Assistant
**Status:** PRODUCTION READY
