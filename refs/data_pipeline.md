# CLM Data Pipeline Architecture

![Architecture Diagram](file:///C:/Users/ANH%20DUY/.gemini/antigravity/brain/c7c18635-37bb-470a-b1e1-84f0533cd444/clm_data_pipeline_diagram_1777434824134.png)

This document describes the flow of log data from collection to visualization and integrity verification.

## 1. Pipeline Overview

```mermaid
graph TD
    subgraph "Log Sources (Monitored Host)"
        A1[/var/log/auth.log/]
        A2[/var/log/nginx/access.log/]
        A3[/var/log/syslog/]
    end

    subgraph "Shipper (Filebeat)"
        B[Filebeat Service]
    end

    subgraph "Processor (Logstash)"
        C{Input: Beats 5044}
        D[Grok: Parsing & Extraction]
        E[Security Logic: SQLi/XSS Detection]
        F[Integrity: HMAC-SHA256 Signing]
    end

    subgraph "Storage & Search (Elasticsearch)"
        G[(logs-* Index)]
        H[(security-alerts-* Index)]
    end

    subgraph "Visualization (Kibana)"
        I[Dashboards & Discover]
    end

    subgraph "Integrity Verification"
        J[verify_log_integrity.py]
    end

    %% Data Flow
    A1 & A2 & A3 -->|Plain Text Logs| B
    B -->|Structured Events| C
    C --> D
    D --> E
    E --> F
    F -->|Encrypted TLS| G
    F -->|Alerts Only| H
    G & H --> I
    G -.->|Audit Check| J
    J -.->|Re-calculate & Compare| G
```

## 2. Detailed Data Flow

### Step 1: Collection (Filebeat)
- **Input**: Monitors specific log files on the host system.
- **Processing**: Adds metadata like `host.name`, `log_type`, and `environment`.
- **Output**: Forwards events to Logstash over the network (Beats protocol).

### Step 2: Processing & Enrichment (Logstash)
- **Parsing**: Uses **Grok** filters to turn unstructured strings (like Nginx logs) into structured fields (IP, Status Code, User-Agent).
- **Security Analysis**: Scans request URIs for malicious patterns like `UNION SELECT` or `<script>`.
- **Integrity Protection**: A Ruby filter calculates an **HMAC-SHA256** signature using a secret key. This "seals" the log entry before it is stored.
- **Normalization**: Standardizes timestamps and field names (ECS compliance).

### Step 3: Indexing & Storage (Elasticsearch)
- Data is stored in daily indices.
- **Security Alerts** are duplicated to a special index for faster incident response.
- Communication is fully encrypted via **TLS/SSL**.

### Step 4: Visualization (Kibana)
- Analysts use Kibana to query the data and view security dashboards.

### Step 5: Verification (Python Script)
- To ensure no one has tampered with the logs (even an admin with ES access), the `verify_log_integrity.py` script:
    1. Fetches a log entry from Elasticsearch.
    2. Re-calculates the HMAC using the secret key.
    3. Compares it with the stored `integrity.hmac` field.
