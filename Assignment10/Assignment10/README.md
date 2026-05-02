## SETUP ELASTIC STACK

## Configuration by Duy

---

## 1. Folder Structure

    ```
    elk-project-duy/
    ├── .env                       <-- Secrets (DO NOT commit)
    ├── docker-compose.yaml        <-- Main compose file
    ├── certs/                     <-- CA and per-service certificates
    │   ├── ca.crt
    │   ├── ca.p12
    │   ├── elasticsearch/
    │   │   ├── elasticsearch.crt
    │   │   └── elasticsearch.key
    │   ├── kibana/
    │   │   ├── kibana.crt
    │   │   └── kibana.key
    │   └── logstash/
    │       ├── logstash.crt
    │       └── logstash.key
    ├── kibana/
    │   └── kibana.yml              <-- Kibana config (security, alerting, SSL)
    ├── filebeat/
    │   └── filebeat.yml           <-- Log shipper inputs and output config
    └── logstash/
        ├── logstash.yml            <-- Logstash settings (monitoring disabled)
        └── pipeline/
            └── main.conf          <-- Log parsing, HMAC integrity, ES output
    ```

---

## 2. Secrets Management (.env)

All credentials are stored in a single `.env` file in the project root.
Docker Compose loads this file automatically — no manual `export` is needed.

| Variable                  | Used by                    | Purpose                                        |
| ------------------------- | -------------------------- | ---------------------------------------------- |
| `ELASTIC_PASSWORD`        | Elasticsearch, Logstash    | Password for the `elastic` superuser           |
| `KIBANA_SYSTEM_PASSWORD`  | Kibana                     | Password for the `kibana_system` built-in user |
| `LOG_HMAC_KEY`            | Logstash                   | 256-bit key for HMAC-SHA256 log signing        |
| `KIBANA_ENCRYPTION_KEY`   | Kibana                     | Saved-object and session encryption            |
| `KIBANA_REPORTING_KEY`    | Kibana                     | Report encryption key                          |

**The `.env` file must not be committed to version control.**
Add it to `.gitignore`:

```bash
echo ".env" >> .gitignore
```

To regenerate all secrets (e.g., after a suspected compromise):

```bash
python3 -c "
import secrets, string

def alphanum(n):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(n))

print('ELASTIC_PASSWORD=' + alphanum(24))
print('KIBANA_SYSTEM_PASSWORD=' + alphanum(24))
print('LOG_HMAC_KEY=' + secrets.token_hex(32))
print('KIBANA_ENCRYPTION_KEY=' + secrets.token_hex(32))
print('KIBANA_REPORTING_KEY=' + secrets.token_hex(32))
" > .env
```

Then restart with a clean volume: `docker-compose down -v && docker-compose up -d`

---

## 3. Key Design Decisions

- **Authentication**: Logstash uses the `elastic` superuser (`ELASTIC_PASSWORD`).
  Kibana uses the `kibana_system` built-in user (`KIBANA_SYSTEM_PASSWORD`) —
  Kibana 8.x forbids the `elastic` superuser for its own connection to
  Elasticsearch. The `kibana_system` password must be set once via the
  Elasticsearch API after the first startup (see Phase 2).
- **TLS scope**: All Logstash → Elasticsearch and Kibana → Elasticsearch
  traffic is TLS-encrypted. Filebeat → Logstash runs unencrypted because
  no filebeat client certificate is present in this cert structure.
- **Log inputs (Filebeat)**: Replaces the module-based approach with explicit
  `filebeat.inputs` entries covering auth, nginx, syslog, firewall, and
  application logs.
- **Log processing (Logstash)**: Full grok parsing for SSH, Nginx, and UFW;
  SQL injection and XSS detection; HMAC-SHA256 integrity signing on every
  event; dual-index output (`logs-*` and `security-alerts-*`).
- **Kibana**: Served over HTTPS (port 5601) using the kibana cert pair.
  Security Solution is enabled with default indices `logs-*`,
  `filebeat-*`, and `security-alerts-*`.

---

## 4. Step-by-Step Deployment Guide

### Phase 0: Clean Reset (Start Over)

Run this to tear down everything and return to a blank slate before
re-running the full setup from Phase 1.

```bash
# Stop and remove containers, named volumes (es_data), and the Docker network
docker-compose down -v --remove-orphans

# Remove all generated certificate files (keeps instances.yaml)
sudo rm -rf certs/elasticsearch certs/kibana certs/logstash && sudo rm -f certs/ca.crt certs/ca.p12 certs/bundle.zip

# (Optional) Regenerate secrets in .env
python3 -c "
import secrets, string

def alphanum(n):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(n))

print('ELASTIC_PASSWORD=' + alphanum(24))
print('KIBANA_SYSTEM_PASSWORD=' + alphanum(24))
print('LOG_HMAC_KEY=' + secrets.token_hex(32))
print('KIBANA_ENCRYPTION_KEY=' + secrets.token_hex(32))
print('KIBANA_REPORTING_KEY=' + secrets.token_hex(32))
" > .env
```

Then continue from Phase 1 below.

---

### Phase 1: Certificate Generation

Certificates must be generated before the first `docker-compose up`.

**Step 0 — Allow the container to write to `certs/`:**

On macOS, Docker Desktop runs containers in a Linux VM. The container's
Elasticsearch process uses UID 1000, which is different from your Mac user UID.
Make the directory world-writable so both UIDs can write to it:

```bash
chmod 777 ./certs
```

**Step 1 — Generate the CA (PKCS12):**

```bash
docker run --rm \
  -v "$(pwd)/certs:/certs" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0 \
  bin/elasticsearch-certutil ca --out /certs/ca.p12 --pass ""
```

**Step 2 — Export the CA public certificate (PEM):**

`ca.p12` contains both the CA cert and private key but is not directly usable
by the services. This step extracts `ca.crt` (PEM format), which every service
mounts as its trust anchor. **Skipping this step causes Elasticsearch to fail
on startup** with `ca.crt does not exist`.

```bash
docker run --rm \
  -v "$(pwd)/certs:/certs" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0 \
  bash -c "openssl pkcs12 -in /certs/ca.p12 -nokeys -out /certs/ca.crt -passin pass:"
```

**Step 3 — Generate node certificates (PEM format):**

Create `certs/instances.yaml` with the following content:

```yaml
instances:
  - name: elasticsearch
    dns: [elasticsearch]
  - name: logstash
    dns: [logstash]
  - name: kibana
    dns: [kibana]
```

Then run:

```bash
docker run --rm \
  -v "$(pwd)/certs:/certs" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0 \
  bin/elasticsearch-certutil cert \
    --ca /certs/ca.p12 --ca-pass "" \
    --pem \
    --in /certs/instances.yaml \
    --out /certs/bundle.zip --silent

unzip certs/bundle.zip -d certs/
```

**Step 4 — Restore ownership and permissions:**

```bash
sudo chown -R $(id -u):$(id -g) ./certs
chmod 755 ./certs
```

The unzipped output places each service's cert and key into a matching
subdirectory (`certs/elasticsearch/`, `certs/logstash/`, `certs/kibana/`),
which matches the volume mount paths used in docker-compose.

---

### Phase 2: Deployment

#### Local (Mac / Windows / Linux laptop)

**Step 1 — Start Elasticsearch first and set the `kibana_system` password:**

```bash
docker-compose up -d elasticsearch
# Wait for Elasticsearch to become healthy (about 30–60 s), then:
docker exec elasticsearch curl -sk \
  -u "elastic:${ELASTIC_PASSWORD}" \
  -X POST "https://localhost:9200/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}"
```

An empty `{}` response means success.

**Step 2 — Start remaining services:**

```bash
docker-compose up -d
```

Kibana is served over HTTPS. Open `https://localhost:5601` and accept the
self-signed certificate warning (the cert is signed by the project CA, not a
public authority). Log in with:

- **Username**: `elastic`
- **Password**: value of `ELASTIC_PASSWORD` in `.env`

#### Linux Server (Ubuntu / Debian)

**Fix file ownership** (Elasticsearch requires UID 1000):

```bash
sudo chown -R 1000:1000 ./certs
```

**Increase virtual memory limit** (required by Elasticsearch):

```bash
sudo sysctl -w vm.max_map_count=262144
```

**Open firewall ports:**

```bash
sudo ufw allow 5601/tcp   # Kibana UI
sudo ufw allow 9200/tcp   # Elasticsearch API (optional, for direct access)
```

**Start:**

```bash
docker-compose up -d
```

**Verify all containers are healthy:**

```bash
docker-compose ps
docker logs elasticsearch --tail 30
```

---

## 5. Rotating Secrets

To rotate all secrets, regenerate `.env` (see the command in Section 2) and
restart with a clean volume so Elasticsearch re-bootstraps with the new password:

```bash
docker-compose down -v   # removes es_data volume
# regenerate .env here
docker-compose up -d
```

To rotate only `ELASTIC_PASSWORD` or `KIBANA_SYSTEM_PASSWORD` without losing
indexed data, update the value in `.env`, push the change into Elasticsearch,
then restart the affected service:

```bash
# Rotate elastic superuser password
curl -k -u "elastic:<current-password>" \
  -X POST "https://localhost:9200/_security/user/elastic/_password" \
  -H "Content-Type: application/json" \
  -d '{"password":"<new-password>"}'
# Update ELASTIC_PASSWORD in .env, then:
docker-compose restart logstash

# Rotate kibana_system password
curl -k -u "elastic:<elastic-password>" \
  -X POST "https://localhost:9200/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" \
  -d '{"password":"<new-kibana-system-password>"}'
# Update KIBANA_SYSTEM_PASSWORD in .env, then:
docker-compose restart kibana
```

---

## 6. Log Integrity Verification

Each log event is signed with HMAC-SHA256 before indexing. The signing key
is set via `LOG_HMAC_KEY` in docker-compose (default: `YourSuperSecretKey123`).

The payload format is:

```
@timestamp | host.name | source.ip | user.name | message
```

To verify a stored document, run the Python script from the report appendix:

```bash
pip install elasticsearch
# Read the key from .env
export LOG_HMAC_KEY=$(grep LOG_HMAC_KEY .env | cut -d= -f2)
python verify_log_integrity.py logs-2024.01.15 <doc-id>
```

---

## 7. Troubleshooting

### Issue 1 — Kibana fatal: `definition for this key is missing`

**Symptom** (`docker logs kibana`):

```
FATAL  Error: [config validation of [xpack.actions].enabled]: definition for this key is missing
```

**Root cause**: Kibana 8.x treats any unrecognised config key as a fatal
validation error on startup. Several keys that existed in older versions were
removed because the features they toggled are now always enabled or were
restructured.

**Fix**: `kibana/kibana.yml` was updated to remove all invalid keys.

| Removed key                                                      | Reason                                                                       |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `xpack.actions.enabled`                                          | Removed in 8.x — actions framework always enabled                            |
| `xpack.alerting.enabled`                                         | Removed in 8.x — alerting always enabled                                     |
| `xpack.canvas.enabled`                                           | Removed in 8.11+                                                             |
| `xpack.security.sessionTimeout`                                  | Deprecated; replaced by `xpack.security.session.idleTimeout` and `.lifespan` |
| `xpack.ml.enabled`                                               | ML available on basic license without a toggle                               |
| `monitoring.ui.enabled` / `monitoring.kibana.collection.enabled` | Wrong namespace; moved to `xpack.monitoring.*` in 8.x                        |
| `xpack.monitoring.elasticsearch.*`                               | Deprecated monitoring config block                                           |
| `xpack.infra.enabled`, `xpack.apm.enabled`                       | Not valid standalone toggles in 8.12                                         |

If a future Kibana upgrade rejects another key, identify it in the log and
remove it from `kibana/kibana.yml`.

---

### Issue 2 — Logstash: `Connection refused` to `http://elasticsearch:9200`

**Symptom** (`docker logs logstash`):

```
[WARN][logstash.licensechecker.licensereader] Marking url as dead.
  Last error: Elasticsearch Unreachable: http://elasticsearch:9200/ — Connection refused
[ERROR][logstash.monitoring.internalpipelinesource] Failed to fetch X-Pack
  information from Elasticsearch.
```

**Root cause**: Logstash has a built-in X-Pack monitoring/license checker that
runs independently of the pipeline. It connects to Elasticsearch using
**plain HTTP** (`http://`) by default. Because Elasticsearch is configured
with `xpack.security.http.ssl.enabled=true`, it only accepts **HTTPS** and
rejects plain HTTP connections — hence "Connection refused". This is a
separate connection from the pipeline output, which correctly uses HTTPS.

**Fix**: `logstash/logstash.yml` (mounted at
`/usr/share/logstash/config/logstash.yml`) disables the monitoring subsystem
entirely:

```yaml
xpack.monitoring.enabled: false
monitoring.enabled: false
```

This stops the license checker from making any connection to Elasticsearch,
eliminating the error loop.

---

### Issue 3 — Logstash/Kibana start before Elasticsearch is ready

**Symptom**: Logstash or Kibana logs show connection errors immediately after
`docker-compose up`, even though Elasticsearch eventually becomes healthy.

**Root cause**: `depends_on: elasticsearch` only waits for the Elasticsearch
**container process** to start — not for Elasticsearch itself to finish
bootstrapping (which takes 30–60 s). Both services attempt to connect during
that window and fail.

**Fix**: `docker-compose.yaml` adds a healthcheck to the Elasticsearch service
and updates Logstash and Kibana to use `condition: service_healthy`:

```yaml
# elasticsearch service
healthcheck:
  test: ["CMD-SHELL", "curl -sk https://localhost:9200 -o /dev/null && echo ok"]
  interval: 15s
  timeout: 10s
  retries: 12
  start_period: 60s

# logstash and kibana services
depends_on:
  elasticsearch:
    condition: service_healthy
```

A 401 (Unauthorized) HTTP response from ES still satisfies the healthcheck —
it confirms TLS is working and ES is accepting connections.
If ES takes longer than `start_period + (interval × retries)` on slow hardware,
increase `start_period` or `retries`.

---

### Issue 4 — Elasticsearch warns: `received plaintext http traffic on an https channel`

**Symptom** (`docker logs elasticsearch`):
```
received plaintext http traffic on an https channel, closing connection
Netty4HttpChannel{remoteAddress=/172.19.0.4:...}
```

**Root cause**: In the Logstash elasticsearch output plugin shipped with
Logstash 8.x, `ssl => true` and `cacert =>` are deprecated aliases that are
silently ignored in newer plugin versions. When ignored, the plugin defaults
to unencrypted HTTP — even though the hosts URL contains `https://`.

**Fix**: `logstash/pipeline/main.conf` updated to use the current parameter
names:

| Old (deprecated, ignored) | New (Logstash 8.x)              |
|---------------------------|---------------------------------|
| `ssl => true`             | `ssl_enabled => true`           |
| `cacert => "..."`         | `ssl_certificate_authorities => ["..."]` |

After updating `main.conf`, restart Logstash:
```bash
docker-compose restart logstash
```

---

### Issue 5 — Elasticsearch fatal: `ca.crt does not exist`

**Symptom** (`docker logs elasticsearch`):
```
failed to load SSL configuration [xpack.security.transport.ssl] -
cannot read configured PEM certificate_authorities
[/usr/share/elasticsearch/config/certs/ca.crt] because the file does not exist
```

**Root cause**: `elasticsearch-certutil ca` produces `ca.p12` (PKCS12 format
containing both the CA cert and its private key). The `bundle.zip` from the
`cert` command contains only node cert/key pairs — neither command automatically
extracts `ca.crt` (PEM format) as a standalone file. All four services mount
`ca.crt` as their TLS trust anchor, so its absence is fatal.

**Fix**: extract `ca.crt` from `ca.p12` inside the Elasticsearch container
(which has OpenSSL) after Step 1 and before `docker-compose up`:

```bash
chmod 777 ./certs
docker run --rm \
  -v "$(pwd)/certs:/certs" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0 \
  bash -c "openssl pkcs12 -in /certs/ca.p12 -nokeys -out /certs/ca.crt -passin pass:"
sudo chown -R $(id -u):$(id -g) ./certs
```

---

### Issue 5b — `AccessDeniedException` during certificate generation

**Symptom**:

```
Exception in thread "main" java.nio.file.AccessDeniedException: /certs/ca.p12
```

**Root cause**: On macOS, Docker Desktop runs containers in a Linux VM. The
`elasticsearch-certutil` process runs as UID 1000 inside the container. The
`certs/` directory on the host is owned by your Mac user (a different UID),
so UID 1000 is denied write access.

`--user $(id -u):$(id -g)` does **not** fix this when the directory was
previously `chown`-ed to 1000:1000, because then your Mac UID is the one
without write access — the two approaches cancel each other out.

**Fix**: keep the directory owned by your Mac user, and grant world-write
permission so the container's UID 1000 can also write to it. Drop the
`--user` flag entirely.

```bash
# If you previously ran sudo chown -R 1000:1000 ./certs, restore first:
sudo chown -R $(id -u):$(id -g) ./certs

chmod 777 ./certs

docker run --rm -v "$(pwd)/certs:/certs" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0 \
  bin/elasticsearch-certutil ca --out /certs/ca.p12 --pass ""

# Restore after generation
chmod 755 ./certs
```

---

### Issue 6 — Kibana fatal: `elastic` superuser is forbidden

**Symptom** (`docker logs kibana`):

```
FATAL  Error: [config validation of [elasticsearch].username]:
  value of "elastic" is forbidden. This is a superuser account that cannot
  write to system indices that Kibana needs to function. Use a service
  account token instead.
```

**Root cause**: Kibana 8.x explicitly rejects the `elastic` superuser for its
internal Elasticsearch connection. Kibana needs to write to protected system
indices (`.kibana`, `.kibana_task_manager`, etc.) and the framework enforces
that this is done through a restricted account rather than a superuser.

**Fix**:
1. Add `KIBANA_SYSTEM_PASSWORD` to `.env` with a strong random value.
2. Set the password on the running Elasticsearch instance:
   ```bash
   docker exec elasticsearch curl -sk \
     -u "elastic:${ELASTIC_PASSWORD}" \
     -X POST "https://localhost:9200/_security/user/kibana_system/_password" \
     -H "Content-Type: application/json" \
     -d "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}"
   ```
   An empty `{}` response confirms success.
3. Update `kibana/kibana.yml`:
   ```yaml
   elasticsearch.username: "kibana_system"
   elasticsearch.password: "${KIBANA_SYSTEM_PASSWORD}"
   ```
4. Pass the variable to the Kibana container in `docker-compose.yml`:
   ```yaml
   environment:
     - KIBANA_SYSTEM_PASSWORD=${KIBANA_SYSTEM_PASSWORD}
   ```
5. Restart Kibana: `docker-compose restart kibana`

---

### Issue 7 — Filebeat warnings about missing log paths (e.g. Nginx)

**Symptom**: Filebeat logs warnings like
`No files matching /var/log/nginx/access.log`.

**Root cause / resolution**: Filebeat skips paths that do not exist at startup
and polls for them silently. This is expected behaviour when a monitored
service (e.g. Nginx) has not yet been installed. The warnings are harmless and
will stop as soon as the log files appear. No configuration change is needed;
Filebeat will begin collecting those logs automatically once Nginx is running.

---

## 8. Security Indices

| Index pattern       | Contents                                                               |
| ------------------- | ---------------------------------------------------------------------- |
| `logs-YYYY.MM.dd`   | All ingested log events                                                |
| `security-alerts-*` | Events tagged `security_alert` (SSH brute force, SQLi, XSS, port scan) |

Detection tags applied by Logstash:

| Tag                  | Trigger                                      |
| -------------------- | -------------------------------------------- |
| `ssh_failed_login`   | `Failed password` in auth log                |
| `sql_injection`      | SQLi patterns in Nginx request URI           |
| `xss`                | Script/event-handler patterns in request URI |
| `blocked_connection` | UFW `BLOCK` action in firewall log           |
| `access_denied`      | HTTP 401 or 403 response codes               |
