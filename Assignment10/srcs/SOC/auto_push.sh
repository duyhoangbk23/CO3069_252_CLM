#!/bin/bash
# =============================================================================
# auto_push.sh — Tự động theo dõi và đẩy log lên Elasticsearch
# CHẠY TỪ: ~/CO3069_252_CLM/srcs/SOC/
# .env nằm ở: ~/CO3069_252_CLM/srcs/.env  (tức là ../.env so với thư mục này)
# import_to_elastic.py nằm cùng thư mục với script này
# =============================================================================

echo "🚀 Hệ thống Canh gác và Tự động đẩy Log đang chạy..."
echo "Nhấn Ctrl+C để dừng."

# ─── Xác định đường dẫn tuyệt đối từ vị trí script ──────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# SCRIPT_DIR = ~/CO3069_252_CLM/srcs/SOC
# ENV_FILE   = ~/CO3069_252_CLM/srcs/.env
ENV_FILE="$SCRIPT_DIR/../.env"
IMPORT_SCRIPT="$SCRIPT_DIR/import_to_elastic.py"

# ─── Đọc ELASTIC_PASSWORD ────────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    echo "❌ Không tìm thấy file .env tại: $ENV_FILE"
    echo "   Đảm bảo file srcs/.env tồn tại"
    exit 1
fi

EPASS=$(grep '^ELASTIC_PASSWORD=' "$ENV_FILE" | cut -d= -f2 | tr -d '\r\n ')

if [[ -z "$EPASS" ]]; then
    echo "❌ ELASTIC_PASSWORD trống trong $ENV_FILE"
    echo "   Kiểm tra: cat $ENV_FILE"
    exit 1
fi

echo "✅ Đọc được ELASTIC_PASSWORD từ $ENV_FILE"
echo "📂 Script import: $IMPORT_SCRIPT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ─── Vòng lặp chính ──────────────────────────────────────────────────────────
while true; do
    PUSHED=false

    # Kiểm tra Nginx access.log
    if [[ -s /var/log/nginx/access.log ]]; then
        echo ""
        echo "🚨 $(date '+%H:%M:%S') Phát hiện tấn công Web! Đang đẩy lên Elasticsearch..."
        python3 "$IMPORT_SCRIPT" \
            --password "$EPASS" \
            --nginx-log /var/log/nginx/access.log \
            --auth-log /dev/null \
            --ufw-log /dev/null
        sudo bash -c '> /var/log/nginx/access.log'
        echo "✅ Đã đẩy và dọn dẹp Nginx log"
        PUSHED=true
    fi

    # Kiểm tra auth.log
    if [[ -s /var/log/auth.log ]]; then
        echo ""
        echo "🚨 $(date '+%H:%M:%S') Phát hiện tấn công SSH! Đang đẩy lên Elasticsearch..."
        python3 "$IMPORT_SCRIPT" \
            --password "$EPASS" \
            --auth-log /var/log/auth.log \
            --nginx-log /dev/null \
            --ufw-log /dev/null
        sudo bash -c '> /var/log/auth.log'
        echo "✅ Đã đẩy và dọn dẹp SSH log"
        PUSHED=true
    fi

    # Kiểm tra ufw.log
    if [[ -s /var/log/ufw.log ]]; then
        echo ""
        echo "🚨 $(date '+%H:%M:%S') Phát hiện firewall block! Đang đẩy lên Elasticsearch..."
        python3 "$IMPORT_SCRIPT" \
            --password "$EPASS" \
            --ufw-log /var/log/ufw.log \
            --auth-log /dev/null \
            --nginx-log /dev/null
        sudo bash -c '> /var/log/ufw.log'
        echo "✅ Đã đẩy và dọn dẹp UFW log"
        PUSHED=true
    fi

    if [[ "$PUSHED" == false ]]; then
        printf "."  # heartbeat khi không có log mới
    fi

    sleep 2
done