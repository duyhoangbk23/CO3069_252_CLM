#!/bin/bash
# =============================================================================
# setup_victim.sh — Tạo máy nạn nhân bằng Docker để test Phase 5
# Victim có SSH + Nginx, dùng để Hydra/Nmap/curl tấn công
# =============================================================================

set -e
GRN='\033[0;32m'; YLW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${YLW}[*] Tạo victim container...${NC}"

# Dừng container cũ nếu có
docker rm -f victim 2>/dev/null || true

# Tạo victim với SSH + Nginx
docker run -d \
  --name victim \
  -p 2222:22 \
  -p 8080:80 \
  ubuntu:22.04 \
  bash -c "
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq &&
    apt-get install -y -qq openssh-server nginx &&
    mkdir -p /run/sshd /var/www/html &&
    
    # Tạo user test
    useradd -m testuser && echo 'testuser:password123' | chpasswd &&
    useradd -m admin && echo 'admin:admin123' | chpasswd &&
    echo 'root:rootpass' | chpasswd &&
    
    # Cho phép SSH root login (để Hydra test)
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config &&
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config &&
    
    # Tạo fake web app với endpoint dễ bị SQLi/XSS
    cat > /var/www/html/index.html << 'HTML'
<!DOCTYPE html><html><body>
<h1>Test Web App</h1>
<form action='/products.php'>ID: <input name='id'><button>Search</button></form>
<form action='/search'>Query: <input name='q'><button>Search</button></form>
</body></html>
HTML
    
    # Config Nginx
    cat > /etc/nginx/sites-available/default << 'NGINX'
server {
    listen 80;
    root /var/www/html;
    index index.html;
    
    location / { try_files \$uri \$uri/ =404; }
    location /products.php { return 200 \"Products: \$arg_id\"; }
    location /search { return 200 \"Search: \$arg_q\"; }
    location /api/login { return 200 \"Login OK\"; }
}
NGINX
    
    nginx &&
    /usr/sbin/sshd -D
  "

echo -e "${YLW}[*] Chờ victim khởi động (15 giây)...${NC}"
sleep 15

# Kiểm tra
echo -e "${YLW}[*] Kiểm tra kết nối...${NC}"

SSH_OK=false
WEB_OK=false

if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p 2222 testuser@localhost \
       -i /dev/null echo "SSH OK" 2>/dev/null; then
    SSH_OK=true
elif curl -s --max-time 3 http://localhost:2222 2>/dev/null; then
    : # port open
fi

# Test bằng password
if sshpass -p password123 ssh -o StrictHostKeyChecking=no -p 2222 testuser@localhost \
   "echo connected" 2>/dev/null; then
    SSH_OK=true
fi

if curl -s --max-time 3 http://localhost:8080 | grep -q "Test Web"; then
    WEB_OK=true
fi

echo ""
echo -e "${GRN}════════════════════════════════════${NC}"
echo -e "${GRN}  Victim Container Ready${NC}"
echo -e "${GRN}════════════════════════════════════${NC}"
echo "  SSH : localhost:2222 (root/rootpass, testuser/password123)"
echo "  Web : http://localhost:8080"
echo ""
echo "  Dùng cho attack_simulation.sh:"
echo -e "  ${YLW}VICTIM=localhost SSH_PORT=2222 WEBPORT=8080 bash attack_simulation.sh --run${NC}"
echo ""
echo "  Dừng victim khi xong:"
echo "  docker rm -f victim"