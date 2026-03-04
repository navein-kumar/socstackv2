#!/usr/bin/env python3
import requests
import json
import time
import sys

NPM_URL = "http://localhost:60081"
NPM_EMAIL = "admin@codesec.in"
NPM_PASS = "SocNpm@2025"

# Get token
print("=== Getting NPM API Token ===")
resp = requests.post(f"{NPM_URL}/api/tokens", json={"identity": NPM_EMAIL, "secret": NPM_PASS})
if resp.status_code != 200:
    print(f"ERROR: Failed to get token: {resp.status_code} {resp.text}")
    sys.exit(1)
TOKEN = resp.json()["token"]
headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
print("Token acquired.")

# Domain -> proxy host ID mapping
DOMAIN_MAP = {
    "sso.codesec.in": 1,
    "wazuh.codesec.in": 2,
    "n8n.codesec.in": 3,
    "cti.codesec.in": 4,
    "hive.codesec.in": 5,
    "cortex.codesec.in": 6,
    "grafana.codesec.in": 7,
    "npm.codesec.in": 8,
}

# Check existing certs
print("\n=== Existing Certificates ===")
certs = requests.get(f"{NPM_URL}/api/nginx/certificates", headers=headers).json()
existing_cert_domains = {}
for c in certs:
    for d in c["domain_names"]:
        existing_cert_domains[d] = c["id"]
    print(f"  Cert ID={c['id']} domains={c['domain_names']} expires={c.get('expires_on','N/A')}")

if not certs:
    print("  No existing certificates found.")

# Domains that need certs
DOMAINS = ["sso.codesec.in", "wazuh.codesec.in", "n8n.codesec.in", "cti.codesec.in",
           "hive.codesec.in", "grafana.codesec.in", "npm.codesec.in"]

cert_map = {}  # domain -> cert_id

# Create certs for domains that don't have one
for domain in DOMAINS:
    if domain in existing_cert_domains:
        print(f"\n=== {domain} already has cert ID={existing_cert_domains[domain]}, skipping ===")
        cert_map[domain] = existing_cert_domains[domain]
        continue

    print(f"\n=== Requesting SSL cert for {domain} ===")
    payload = {
        "domain_names": [domain],
        "meta": {
            "dns_challenge": False
        },
        "provider": "letsencrypt"
    }

    try:
        resp = requests.post(f"{NPM_URL}/api/nginx/certificates", headers=headers, json=payload, timeout=120)
        print(f"  HTTP Status: {resp.status_code}")
        print(f"  Response: {resp.text[:500]}")

        if resp.status_code == 201:
            cert_id = resp.json().get("id")
            cert_map[domain] = cert_id
            print(f"  SUCCESS: Cert created with ID={cert_id}")
        else:
            print(f"  ERROR: Cert creation failed")
    except Exception as e:
        print(f"  EXCEPTION: {e}")

    time.sleep(5)  # Delay between LE requests

# Add cortex (already has cert)
if "cortex.codesec.in" in existing_cert_domains:
    cert_map["cortex.codesec.in"] = existing_cert_domains["cortex.codesec.in"]

# Update proxy hosts with certs
print("\n\n=== Updating Proxy Hosts with SSL ===")
for domain, cert_id in cert_map.items():
    host_id = DOMAIN_MAP.get(domain)
    if not host_id:
        continue

    print(f"\n  Updating {domain} (host={host_id}) with cert={cert_id}...")

    # Get current config
    current = requests.get(f"{NPM_URL}/api/nginx/proxy-hosts/{host_id}", headers=headers).json()

    update_payload = {
        "domain_names": [domain],
        "forward_host": current["forward_host"],
        "forward_port": current["forward_port"],
        "forward_scheme": current["forward_scheme"],
        "certificate_id": cert_id,
        "ssl_forced": True,
        "http2_support": True,
        "block_exploits": True,
        "allow_websocket_upgrade": True,
        "access_list_id": 0,
        "advanced_config": "",
        "meta": {},
        "locations": []
    }

    resp = requests.put(f"{NPM_URL}/api/nginx/proxy-hosts/{host_id}", headers=headers, json=update_payload)
    if resp.status_code == 200:
        print(f"  SUCCESS: {domain} SSL enabled")
    else:
        print(f"  ERROR: {resp.status_code} {resp.text[:300]}")

# Final summary
print("\n\n=== Final Certificate List ===")
certs = requests.get(f"{NPM_URL}/api/nginx/certificates", headers=headers).json()
for c in certs:
    print(f"  Cert ID={c['id']} domains={c['domain_names']} expires={c.get('expires_on','N/A')}")

print("\n=== Final Proxy Host Status ===")
hosts = requests.get(f"{NPM_URL}/api/nginx/proxy-hosts", headers=headers).json()
for h in hosts:
    print(f"  Host ID={h['id']} domain={h['domain_names']} cert_id={h.get('certificate_id',0)} ssl_forced={h.get('ssl_forced',0)}")

print("\n=== DONE ===")
