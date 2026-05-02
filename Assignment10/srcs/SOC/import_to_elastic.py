#!/usr/bin/env python3
"""
import_to_elastic.py — Import log vào Elasticsearch
Cài: pip install elasticsearch
Dùng từ ROOT dự án:
    EPASS=$(grep '^ELASTIC_PASSWORD=' srcs/.env | cut -d= -f2 | tr -d '\r\n ')
    python3 srcs/SOC/import_to_elastic.py --password $EPASS
"""

import argparse
import os
import re
import sys
from datetime import datetime

try:
    from elasticsearch import Elasticsearch, helpers
except ImportError:
    print("[!] Cài thư viện: pip install elasticsearch")
    sys.exit(1)

# ─── Regex patterns khớp với Logstash main.conf grok ──────────────────────────
SYSLOG_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+(?P<host>\S+)"
    r"\s+(?P<proc>\S+?)(?:\[\d+\])?:\s+(?P<msg>.+)"
)
NGINX_RE = re.compile(
    r'(?P<ip>[\d.]+) - (?P<ident>\S+) \[(?P<time>[^\]]+)\]'
    r' "(?P<method>\w+) (?P<path>\S+) HTTP/[\d.]+"'
    r' (?P<status>\d+) (?P<size>\d+)'
    r' "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

# BUG FIX: Logstash grok "OUT=%{WORD:out_interface}" fails when OUT= is empty.
# generate_logs.py tạo: "IN=eth0 OUT= MAC=..." → OUT rỗng → grok fail → tag_on_failure
# Fix: dùng regex linh hoạt hơn, match cả OUT rỗng và OUT có giá trị
UFW_RE = re.compile(
    r"\[UFW (?P<action>\w+)\]"
    r".*?SRC=(?P<src>[\d.]+)"
    r".*?DST=(?P<dst>[\d.]+)"
    r".*?PROTO=(?P<proto>\w+)"
    r".*?SPT=(?P<sport>\d+)"
    r".*?DPT=(?P<dport>\d+)"
)

# Khớp với Logstash SQLi detection regex
SQLI_RE = re.compile(
    r"(?i)(%27|'|--|%23|#|union|select|insert|update|delete|drop|create|alter)"
)
# Khớp với Logstash XSS detection regex
XSS_RE = re.compile(
    r"(?i)(<script|javascript:|onerror=|onload=|<img|<iframe)"
)


def parse_auth_line(line: str, year: int) -> dict | None:
    m = SYSLOG_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(
            f"{year} {m['month']} {m['day'].zfill(2)} {m['time']}",
            "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None

    msg = m["msg"]
    doc = {
        "@timestamp": ts.isoformat() + "Z",
        "host":     {"name": m["host"]},
        "process":  {"name": m["proc"]},
        "message":  msg,
        "log_type": "ssh_auth",
        "tags":     [],
    }

    if "Failed password" in msg:
        doc["tags"] = ["ssh_failed_login", "security_alert", "authentication_failure"]
        doc["alert_level"] = "warning"
        ip_m   = re.search(r"from ([\d.]+)", msg)
        user_m = re.search(r"for (?:invalid user )?(\S+)", msg)
        if ip_m:
            doc["source"]    = {"ip": ip_m.group(1)}
            doc["source_ip"] = ip_m.group(1)
        if user_m:
            doc["user"]     = {"name": user_m.group(1)}
            doc["username"] = user_m.group(1)

    elif "Accepted" in msg:
        doc["tags"] = ["ssh_success", "authentication_success"]
        ip_m   = re.search(r"from ([\d.]+)", msg)
        user_m = re.search(r"for (\S+)", msg)
        if ip_m:
            doc["source"] = {"ip": ip_m.group(1)}
        if user_m:
            doc["user"]   = {"name": user_m.group(1)}

    elif "sudo" in msg or " su[" in msg or "su[" in m["proc"]:
        doc["tags"] = ["privilege_escalation"]
        user_m = re.search(r"(\w+)\s+:", msg)
        if user_m:
            doc["user"] = {"name": user_m.group(1)}

    elif "TLS handshake failure" in msg or "SSL_ERROR" in msg:
        doc["tags"] = ["tls_failure", "security_alert"]

    return doc


def parse_nginx_line(line: str) -> dict | None:
    m = NGINX_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

    path   = m["path"]
    status = int(m["status"])

    doc = {
        "@timestamp":   ts.isoformat(),
        "source":       {"ip": m["ip"]},
        "source_ip":    m["ip"],
        "http": {
            "method":   m["method"],
            "request":  {"method": m["method"]},
            "response": {"status_code": status, "body": {"bytes": int(m["size"])}},
        },
        "http_method":   m["method"],
        "response_code": str(status),
        "url":           {"path": path},
        "request_uri":   path,
        "user_agent":    {"original": m["ua"]},
        "log_type":      "nginx_access",
        "tags":          [],
    }

    if SQLI_RE.search(path):
        doc["tags"]        = ["sql_injection", "web_attack", "security_alert"]
        doc["alert_level"] = "critical"
    elif XSS_RE.search(path):
        doc["tags"]        = ["xss", "web_attack", "security_alert"]
        doc["alert_level"] = "critical"
    elif status in [401, 403]:
        doc["tags"]        = ["access_denied", "security_alert"]
        doc["alert_level"] = "warning"
    elif m["ua"] and ("Nmap" in m["ua"] or "scanner" in m["ua"].lower()):
        doc["tags"]        = ["port_scan", "security_alert"]
        doc["alert_level"] = "warning"

    return doc


def parse_ufw_line(line: str, year: int) -> dict | None:
    """
    BUG FIX: Logstash grok FAILS khi OUT= rỗng.
    generate_logs.py tạo: "IN=eth0 OUT= MAC=..."
    Logstash grok pattern: "OUT=%{WORD:out_interface}" — WORD không match empty string
    Fix: Python regex dùng .* để match linh hoạt, không yêu cầu OUT có giá trị
    """
    m = UFW_RE.search(line.strip())
    if not m:
        return None

    ts_m = SYSLOG_RE.match(line.strip())
    if not ts_m:
        return None
    try:
        ts = datetime.strptime(
            f"{year} {ts_m['month']} {ts_m['day'].zfill(2)} {ts_m['time']}",
            "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None

    doc = {
        "@timestamp":     ts.isoformat() + "Z",
        "message":        line.strip(),
        "log_type":       "firewall",
        "source":         {"ip": m["src"]},
        "source_ip":      m["src"],
        "destination":    {"ip": m["dst"]},
        "dest_ip":        m["dst"],
        "network":        {"protocol": m["proto"]},
        "firewall_action": m["action"],
        "tags":           ["firewall", "network_traffic"],
    }
    if m["action"] == "BLOCK":
        doc["tags"]       += ["blocked_connection", "potential_port_scan", "security_alert"]
        doc["alert_level"] = "warning"
    return doc


def bulk_import(es: Elasticsearch, index: str, docs: list[dict]) -> tuple[int, int]:
    if not docs:
        return 0, 0
    actions = [{"_index": index, "_source": d} for d in docs]
    success, errors = helpers.bulk(es, actions, raise_on_error=False, chunk_size=500)
    return success, len(errors) if errors else 0


def main():
    today = datetime.now().strftime("%Y.%m.%d")

    parser = argparse.ArgumentParser(description="Import log vào Elasticsearch (HTTPS)")
    parser.add_argument("--host",      default="https://localhost:9200")
    parser.add_argument("--user",      default="elastic")
    parser.add_argument("--password",  required=True,
                        help="Lấy từ srcs/.env: ELASTIC_PASSWORD")
    parser.add_argument("--ca-cert",   default="",
                        help="Path to ca.crt — để trống thì skip verify (OK với cert tự ký)")
    # BUG FIX: default paths đúng với cấu trúc thực tế
    # Script chạy từ ROOT: ~/CO3069_252_CLM/
    # Nên path phải là srcs/SOC/logs_sample/...
    parser.add_argument("--auth-log",  default="srcs/SOC/logs_sample/auth.log")
    parser.add_argument("--nginx-log", default="srcs/SOC/logs_sample/nginx_access.log")
    parser.add_argument("--ufw-log",   default="srcs/SOC/logs_sample/ufw.log")
    args = parser.parse_args()

    # ── Kết nối Elasticsearch ─────────────────────────────────────────────────
    es_kwargs: dict = {"basic_auth": (args.user, args.password)}

    if args.ca_cert and os.path.exists(args.ca_cert):
        es_kwargs["ca_certs"]     = args.ca_cert
        es_kwargs["verify_certs"] = True
        print(f"[*] TLS verify với CA: {args.ca_cert}")
    else:
        es_kwargs["verify_certs"] = False
        es_kwargs["ssl_show_warn"] = False
        print("[*] Skip SSL verify (cert tự ký — bình thường với stack này)")

    es = Elasticsearch(args.host, **es_kwargs)

    try:
        info = es.info()
        ver  = info["version"]["number"]
        print(f"[+] Kết nối thành công: {args.host} (ES {ver})")
    except Exception as e:
        print(f"[!] Lỗi kết nối Elasticsearch: {e}")
        print("    Kiểm tra: docker compose ps | grep elasticsearch")
        print("    Kiểm tra: sudo sysctl vm.max_map_count (phải >= 262144)")
        return

    year      = datetime.now().year
    today_str = today

    # ── Helper import function ────────────────────────────────────────────────
    def do_import(log_path: str, parse_fn, log_name: str):
        # BUG FIX: /dev/null là path hợp lệ nhưng rỗng → auto_push.sh dùng /dev/null
        # khi muốn skip 1 loại log. Cần check cả size > 0.
        if not log_path or log_path in ("/dev/null", "") or not os.path.exists(log_path):
            return
        if os.path.getsize(log_path) == 0:
            return

        with open(log_path, encoding="utf-8", errors="replace") as f:
            if log_name == "UFW":
                all_docs = [d for line in f if (d := parse_fn(line, year))]
            elif log_name == "Auth":
                all_docs = [d for line in f if (d := parse_fn(line, year))]
            else:
                all_docs = [d for line in f if (d := parse_fn(line))]

        alerts = [d for d in all_docs if "security_alert" in d.get("tags", [])]
        print(f"[*] {log_name}: {len(all_docs)} docs parsed ({len(alerts)} security alerts)")

        ok1, err1 = bulk_import(es, f"logs-{today_str}", all_docs)
        print(f"    → logs-{today_str}: {ok1} OK" + (f", {err1} errors" if err1 else ""))

        if alerts:
            ok2, err2 = bulk_import(es, f"security-alerts-{today_str}", alerts)
            print(f"    → security-alerts-{today_str}: {ok2} OK" + (f", {err2} errors" if err2 else ""))
        else:
            print(f"    → (không có security alert trong file này)")

    # ── Import từng loại log ──────────────────────────────────────────────────
    do_import(args.auth_log,  parse_auth_line,  "Auth")
    do_import(args.nginx_log, parse_nginx_line, "Nginx")
    do_import(args.ufw_log,   parse_ufw_line,   "UFW")

    # ── Kiểm tra kết quả ─────────────────────────────────────────────────────
    print("\n[*] Tổng kết:")
    for idx in [f"logs-{today_str}", f"security-alerts-{today_str}"]:
        try:
            count = es.count(index=idx)["count"]
            print(f"    {idx}: {count:,} docs")
        except Exception:
            print(f"    {idx}: (chưa có dữ liệu)")

    print(f"\n[+] Xong! Kibana: https://localhost:5601")
    print(f"    Discover → chọn 'All Logs' (logs-*) hoặc 'Security Alerts' (security-alerts-*)")


if __name__ == "__main__":
    main()