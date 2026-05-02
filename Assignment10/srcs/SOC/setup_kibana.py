#!/usr/bin/env python3
"""
setup_kibana.py — Tạo Data Views + Dashboard + Import Detection Rules
Khớp với stack thực tế: HTTPS Kibana, index pattern logs-*, security-alerts-*

Dùng:
    EPASS=$(grep ELASTIC_PASSWORD srcs/.env | cut -d= -f2 | tr -d '\\r')
    python3 srcs/SOC/setup_kibana.py --password $EPASS
"""

import argparse, json, time, sys, os

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)

KB_BASE = ""
SESSION = None


def api(method: str, path: str, data=None, params=None):
    url = f"{KB_BASE}/api/{path}"
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    r = getattr(SESSION, method)(
        url, headers=headers, json=data, params=params,
        verify=False, timeout=30
    )
    return r


def wait_kibana(retries=24):
    print("[*] Chờ Kibana sẵn sàng", end="", flush=True)
    for _ in range(retries):
        try:
            r = SESSION.get(f"{KB_BASE}/api/status", verify=False, timeout=8)
            if r.status_code == 200:
                level = r.json().get("status", {}).get("overall", {}).get("level", "")
                if level in ["available", "degraded"]:
                    print(f" OK ({level})")
                    return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(5)
    print("\n[!] Kibana timeout")
    return False


# ── Data Views (Index Patterns) ────────────────────────────────────────────────
def create_data_views():
    """
    Tạo data views cho 3 index pattern:
    - logs-*             (tất cả logs từ Logstash daily index)
    - security-alerts-*  (security events có tag security_alert)
    - filebeat-*         (raw Filebeat output nếu cần)
    """
    views = [
        {"id": "dv-logs-all",      "title": "logs-*",            "name": "All Logs"},
        {"id": "dv-security-alerts","title": "security-alerts-*", "name": "Security Alerts"},
        {"id": "dv-filebeat",      "title": "filebeat-*",         "name": "Filebeat Raw"},
    ]
    print("\n[*] Tạo Data Views...")
    for v in views:
        body = {
            "data_view": {
                "id":            v["id"],
                "title":         v["title"],
                "name":          v["name"],
                "timeFieldName": "@timestamp",
            }
        }
        r = api("post", "data_views/data_view", body)
        if r.status_code in [200, 409]:
            print(f"  [+] {v['name']} ({v['title']})")
        else:
            print(f"  [!] {v['name']}: {r.status_code} — {r.text[:100]}")


def import_dashboard(ndjson_path):
    print(f"\n[*] Import Dashboard từ {ndjson_path}...")
    if not os.path.exists(ndjson_path):
        print(f"  [!] Không tìm thấy file {ndjson_path}")
        return

    url = f"{KB_BASE}/api/saved_objects/_import?overwrite=true"
    headers = {"kbn-xsrf": "true"}
    
    with open(ndjson_path, 'rb') as f:
        files = {'file': (os.path.basename(ndjson_path), f, 'application/ndjson')}
        r = SESSION.post(url, headers=headers, files=files, verify=False)
        
        if r.status_code == 200 and r.json().get('success'):
            print("  [+] Dashboard import thành công!")
        else:
            print(f"  [!] Lỗi Import: {r.status_code} - {r.text[:200]}")


def import_detection_rules(rules_file: str):
    """Import 4 detection rules từ all_rules.ndjson"""
    if not os.path.exists(rules_file):
        print(f"\n[!] Không tìm thấy: {rules_file}")
        return

    with open(rules_file) as f:
        try:
            rules = json.load(f)
        except json.JSONDecodeError:
            # NDJSON format (1 JSON per line)
            f.seek(0)
            rules = [json.loads(line) for line in f if line.strip()]

    print(f"\n[*] Import {len(rules)} Detection Rules...")
    for rule in rules:
        r = api("post", "detection_engine/rules", rule)
        if r.status_code in [200, 409]:
            print(f"  [+] {rule.get('name', rule.get('id'))}")
        else:
            # 409 = rule exists, update it
            if r.status_code == 409:
                r2 = api("put", "detection_engine/rules", rule)
                if r2.status_code == 200:
                    print(f"  [~] Updated: {rule.get('name')}")
                else:
                    print(f"  [!] {rule.get('name')}: {r2.status_code} — {r2.text[:100]}")
            else:
                print(f"  [!] {rule.get('name')}: {r.status_code} — {r.text[:120]}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kibana",   default="https://localhost:5601")
    parser.add_argument("--user",     default="elastic")
    parser.add_argument("--password", required=True)
    parser.add_argument("--rules",    default="srcs/SOC/detection_rules/all_rules.ndjson")
    parser.add_argument("--skip-rules",   action="store_true")
    parser.add_argument("--skip-dashboard", action="store_true")
    args = parser.parse_args()

    global KB_BASE, SESSION
    KB_BASE = args.kibana
    SESSION = requests.Session()
    SESSION.auth = (args.user, args.password)

    print(f"[*] Kết nối Kibana: {KB_BASE}")
    if not wait_kibana():
        sys.exit(1)

    create_data_views()

    if not args.skip_dashboard:
        import_dashboard("srcs/SOC/dashboard.ndjson")

    if not args.skip_rules:
        import_detection_rules(args.rules)

    print(f"\n[+] Hoàn tất!")
    print(f"    Dashboard : {KB_BASE}/app/dashboards")
    


if __name__ == "__main__":
    main()