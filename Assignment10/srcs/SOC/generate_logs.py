#!/usr/bin/env python3
"""
generate_logs.py — Tạo log giả lập khớp 100% với Logstash main.conf grok patterns.

BUG FIX trong bản này:
  - UFW log: "OUT= " → "OUT=eth1" (Logstash grok %{WORD} không match empty string)
  - SSH timestamp: đảm bảo format khớp "MMM  d" và "MMM dd"

Cách dùng (chạy từ ROOT: ~/CO3069_252_CLM/):
    python3 srcs/SOC/generate_logs.py
    python3 srcs/SOC/generate_logs.py --lines 3000
    python3 srcs/SOC/generate_logs.py --inject   # append vào /var/log thật
"""

import argparse
import random
import os
import subprocess
from datetime import datetime, timedelta

ATTACKER_IPS = [
    "185.220.101.34", "45.141.84.93",  "194.165.16.73",
    "91.240.118.172", "103.99.0.122",  "10.0.0.50",
    "192.168.1.100",  # khớp generate_test_logs.sh (SSH attacker)
    "192.168.1.101",  # khớp generate_test_logs.sh (SQLi attacker)
    "192.168.1.102",  # khớp generate_test_logs.sh (XSS attacker)
]
LEGIT_IPS    = ["203.162.4.10", "14.225.0.52", "113.161.80.11", "1.53.57.183", "27.72.59.210"]
BRUTE_USERS  = ["root", "admin", "ubuntu", "pi", "user", "test", "oracle", "deploy", "postgres"]
LEGIT_USERS  = ["alice", "bob", "carol"]


def ts_syslog(dt: datetime) -> str:
    """Format khớp với Logstash date filter: 'MMM  d HH:mm:ss' hoặc 'MMM dd HH:mm:ss'"""
    # strftime("%b %d") → "May  1" (ngày < 10) hoặc "May 12" (ngày >= 10)
    # Logstash date filter accept cả 2 format này
    return dt.strftime("%b %d %H:%M:%S")


def ts_nginx(dt: datetime) -> str:
    """Format khớp với Logstash HTTPDATE grok: dd/MMM/yyyy:HH:mm:ss Z"""
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0700")


def rand_dt(base: datetime, spread_min: int = 120) -> datetime:
    return base + timedelta(seconds=random.randint(0, spread_min * 60))


# ─── SSH auth.log ─────────────────────────────────────────────────────────────
def gen_auth_log(n: int, base: datetime) -> list[str]:
    lines = []
    host = "my-server"  # khớp generate_test_logs.sh

    def add(dt, proc, msg):
        pid = random.randint(1000, 9999)
        lines.append(f"{ts_syslog(dt)} {host} {proc}[{pid}]: {msg}")

    # 1. Normal logins
    for _ in range(n // 8):
        dt   = rand_dt(base)
        user = random.choice(LEGIT_USERS)
        ip   = random.choice(LEGIT_IPS)
        port = random.randint(40000, 65000)
        add(dt, "sshd", f"Accepted publickey for {user} from {ip} port {port} ssh2")
        add(dt + timedelta(minutes=random.randint(5, 60)),
            "sshd", f"Disconnected from user {user} {ip} port {port}")

    # 2. Brute-force burst — 30 fails trong 36 giây từ 192.168.1.100
    brute_start    = base + timedelta(minutes=random.randint(5, 20))
    brute_attacker = "192.168.1.100"
    for i in range(30):
        dt   = brute_start + timedelta(seconds=i * 1.2)
        user = random.choice(BRUTE_USERS)
        port = random.randint(40000, 65000)
        add(dt, "sshd", f"Failed password for {user} from {brute_attacker} port {port} ssh2")

    # 3. Scattered failed logins (background noise)
    for _ in range(n // 4):
        dt   = rand_dt(base)
        user = random.choice(BRUTE_USERS)
        ip   = random.choice(ATTACKER_IPS)
        port = random.randint(40000, 65000)
        tag  = "invalid user " if random.random() > 0.5 else ""
        add(dt, "sshd", f"Failed password for {tag}{user} from {ip} port {port} ssh2")

    # 4. Privilege escalation
    for _ in range(n // 15):
        dt   = rand_dt(base)
        user = random.choice(LEGIT_USERS)
        lines.append(f"{ts_syslog(dt)} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash")
        lines.append(f"{ts_syslog(dt + timedelta(seconds=2))} {host} su[{random.randint(1000,9999)}]: Successful su for root by {user}")
        lines.append(f"{ts_syslog(dt + timedelta(seconds=60))} {host} sudo:   {user} : command not allowed ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/passwd")

    # 5. TLS handshake failures
    for _ in range(n // 25):
        dt = rand_dt(base)
        ip = random.choice(ATTACKER_IPS)
        add(dt, "sshd", "error: Could not load host key: /etc/ssh/ssh_host_rsa_key")
        lines.append(f"{ts_syslog(dt)} {host} openssl: TLS handshake failure from {ip}:443 — SSL_ERROR_RX_RECORD_TOO_LONG")

    lines.sort(key=lambda l: l[:15])
    return lines


# ─── Nginx access.log ─────────────────────────────────────────────────────────
def gen_nginx_log(n: int, base: datetime) -> list[str]:
    entries = []

    def add(dt, ip, method, path, status, size, ua="Mozilla/5.0"):
        entries.append(
            f'{ip} - - [{ts_nginx(dt)}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
        )

    # 1. Normal traffic
    normal_paths = ["/", "/index.html", "/api/users", "/api/login",
                    "/static/app.js", "/health", "/robots.txt", "/favicon.ico"]
    for _ in range(n // 3):
        dt = rand_dt(base)
        ip = random.choice(LEGIT_IPS)
        add(dt, ip, "GET", random.choice(normal_paths), 200, random.randint(500, 15000))

    # 2. SQLi — khớp Logstash regex: (?i)(%27|'|union|select|drop)
    sqli_payloads = [
        "/products.php?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--",
        "/api/login?user=%27%20OR%20%271%27%3D%271&pass=test",
        "/api/users?id=%27;%20DROP%20TABLE%20users;--",
        "/search?q=1%27%20AND%20SLEEP(5)--",
        "/products.php?id=1%27%20OR%201%3D1--",
    ]
    sqli_start    = base + timedelta(minutes=40)
    sqli_attacker = "192.168.1.101"  # khớp generate_test_logs.sh
    for i, path in enumerate(sqli_payloads):
        dt = sqli_start + timedelta(seconds=i * 30)
        add(dt, sqli_attacker, "GET", path, random.choice([200, 500]),
            random.randint(200, 2000), ua="sqlmap/1.7.8 (https://sqlmap.org)")
    for _ in range(n // 15):
        dt   = rand_dt(base)
        ip   = random.choice(ATTACKER_IPS)
        path = random.choice(sqli_payloads)
        add(dt, ip, "GET", path, random.choice([200, 403, 500]),
            random.randint(200, 800), ua="python-requests/2.31.0")

    # 3. XSS — khớp Logstash regex: (?i)(<script|javascript:|onerror=|onload=)
    xss_payloads = [
        "/search?q=<script>alert(1)</script>",
        "/search?q=<img%20src=x%20onerror=alert(1)>",
        "/api/comment?text=<svg%20onload=alert(document.cookie)>",
        "/search?q=javascript:alert(1)",
        "/search?q=<iframe%20src=javascript:alert(1)>",
    ]
    xss_start    = base + timedelta(minutes=70)
    xss_attacker = "192.168.1.102"  # khớp generate_test_logs.sh
    for i, path in enumerate(xss_payloads):
        dt = xss_start + timedelta(seconds=i * 20)
        add(dt, xss_attacker, "GET", path, 200, random.randint(300, 5000))

    # 4. Port scan (Nmap UA)
    scan_paths = ["/.env", "/.git/config", "/wp-admin/", "/phpmyadmin/",
                  "/admin/", "/config.php", "/.htaccess", "/backup.sql",
                  "/server-status", "/actuator/health", "/api/v1/users",
                  "/.well-known/security.txt", "/cgi-bin/luci", "/shell", "/passwd"]
    scan_start = base + timedelta(minutes=90)
    scan_ip    = random.choice(ATTACKER_IPS[:4])
    for i, path in enumerate(scan_paths):
        dt = scan_start + timedelta(seconds=i * 0.5)
        add(dt, scan_ip, "GET", path, 404, 153, ua="Nmap Scripting Engine")

    # 5. 401/403 → access_denied
    for _ in range(n // 20):
        dt   = rand_dt(base)
        ip   = random.choice(ATTACKER_IPS)
        path = random.choice(["/admin/", "/api/admin", "/dashboard"])
        add(dt, ip, "GET", path, random.choice([401, 403]), 312)

    entries.sort(key=lambda e: e.split("[")[1].split("]")[0] if "[" in e else "")
    return entries


# ─── UFW firewall log ──────────────────────────────────────────────────────────
def gen_ufw_log(n: int, base: datetime) -> list[str]:
    """
    BUG FIX: Bản cũ tạo "OUT= MAC=..." (OUT rỗng).
    Logstash grok: "OUT=%{WORD:out_interface}" — WORD không match empty string.
    Fix: OUT luôn có giá trị (eth1 cho traffic outbound, hoặc có thể dùng interface thật).
    
    Note: Logstash grok sẽ fail silently với tag_on_failure => [] nên không crash,
    nhưng fields source_ip và dest_ip sẽ không được parse → không tạo security tag.
    """
    lines = []
    host  = "my-server"
    in_ifaces  = ["eth0", "ens33", "enp0s3"]
    out_ifaces = ["eth1", "ens34", "enp0s8"]  # BUG FIX: không để trống

    for _ in range(n):
        dt    = rand_dt(base)
        src   = random.choice(ATTACKER_IPS)
        dst   = "192.168.1.10"
        proto = random.choice(["TCP", "UDP"])
        sport = random.randint(40000, 65000)
        dport = random.choice([22, 23, 3389, 445, 1433, 8080, 3306])
        ts    = ts_syslog(dt)
        # BUG FIX: OUT không còn rỗng
        in_if  = random.choice(in_ifaces)
        out_if = random.choice(out_ifaces)
        lines.append(
            f"{ts} {host} kernel: [12345.678] [UFW BLOCK] "
            f"IN={in_if} OUT={out_if} "
            f"MAC=00:11:22:33:44:55:00:66:77:88:99:aa:08:00 "
            f"SRC={src} DST={dst} LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=12345 DF "
            f"PROTO={proto} SPT={sport} DPT={dport} WINDOW=65535 RES=0x00 SYN URGP=0"
        )

    lines.sort(key=lambda l: l[:15])
    return lines


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Tạo log giả lập khớp với Logstash main.conf"
    )
    parser.add_argument("--output-dir", default="srcs/SOC/logs_sample",
                        help="Thư mục xuất (default: srcs/SOC/logs_sample)")
    parser.add_argument("--lines",      type=int, default=2000)
    parser.add_argument("--hours-back", type=int, default=2)
    parser.add_argument("--inject",     action="store_true",
                        help="Append vào /var/log thật (cần sudo)")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    base = datetime.now() - timedelta(hours=args.hours_back)
    print(f"[*] Sinh log từ {base.strftime('%Y-%m-%d %H:%M')} ...")

    # SSH auth.log
    auth_lines = gen_auth_log(args.lines, base)
    auth_path  = os.path.join(args.output_dir, "auth.log")
    with open(auth_path, "w") as f:
        f.write("\n".join(auth_lines) + "\n")
    print(f"[+] auth.log          → {auth_path}  ({len(auth_lines)} dòng)")

    # Nginx access.log
    nginx_lines = gen_nginx_log(args.lines, base)
    nginx_path  = os.path.join(args.output_dir, "nginx_access.log")
    with open(nginx_path, "w") as f:
        f.write("\n".join(nginx_lines) + "\n")
    print(f"[+] nginx_access.log  → {nginx_path}  ({len(nginx_lines)} dòng)")

    # UFW log
    ufw_lines = gen_ufw_log(args.lines // 5, base)
    ufw_path  = os.path.join(args.output_dir, "ufw.log")
    with open(ufw_path, "w") as f:
        f.write("\n".join(ufw_lines) + "\n")
    print(f"[+] ufw.log           → {ufw_path}  ({len(ufw_lines)} dòng)")

    print("\n[*] Xác nhận attack patterns:")
    brute  = sum(1 for l in auth_lines  if "Failed password" in l)
    sqli   = sum(1 for l in nginx_lines if "UNION" in l or "DROP" in l or "%27" in l)
    xss    = sum(1 for l in nginx_lines if "script" in l or "onerror" in l)
    sudos  = sum(1 for l in auth_lines  if "sudo" in l or "su[" in l)
    ufwblk = sum(1 for l in ufw_lines   if "UFW BLOCK" in l)
    print(f"    SSH brute-force events : {brute}")
    print(f"    SQLi events            : {sqli}")
    print(f"    XSS events             : {xss}")
    print(f"    Sudo/su events         : {sudos}")
    print(f"    UFW BLOCK events       : {ufwblk}")

    if args.inject:
        print("\n[*] Inject vào /var/log ...")
        for src, dst in [
            (auth_path,  "/var/log/auth.log"),
            (nginx_path, "/var/log/nginx/access.log"),
            (ufw_path,   "/var/log/ufw.log"),
        ]:
            subprocess.run(["sudo", "bash", "-c", f"cat {src} >> {dst}"], check=True)
            print(f"    → Appended to {dst}")
        print("[+] Done! Filebeat sẽ đọc trong vài giây.")
    else:
        print("\n[*] Bước tiếp theo:")
        print("    A) python3 srcs/SOC/import_to_elastic.py --password $EPASS")
        print("    B) python3 srcs/SOC/generate_logs.py --inject   (cần sudo)")
        print("    C) sudo bash generate_test_logs.sh")


if __name__ == "__main__":
    main()