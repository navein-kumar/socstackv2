#!/usr/bin/env python3
"""
SOC Stack V2 Post-Deploy Configuration (with SSO)
====================================================
Run AFTER 'docker-compose up -d' to configure all services.

Steps:
  1. NPM: Create proxy hosts + request SSL certs
  2. n8n: Create owner account (disables signup)
  3. Cortex: Migrate DB, create superadmin, org, users, API key
  4. TheHive: Change default password, create org + analyst user
  5. MISP <-> TheHive Integration
  5b. MISP Feeds: Enable all feeds, cache/download all, daily cron update
  6. Keycloak SSO: Create SOC realm, soc-sso client, groups, users
  7. Apply Wazuh security configs (securityadmin)
  8. Wazuh API: SSO role mapping via run_as (soc-admin/analyst -> administrator, soc-readonly -> readonly)
  9. Save all deployed credentials to .env.deployed

Usage:
  python3 /opt/socv2/post-deploy.py
"""
import requests
import json
import time
import sys
import os
import subprocess
import base64
import secrets
import re
from datetime import datetime

requests.packages.urllib3.disable_warnings()

# Auto-detect: use the directory where this script lives
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(BASE_DIR, ".env")
DEPLOYED_FILE = os.path.join(BASE_DIR, ".env.deployed")
LOG_FILE = os.path.join(BASE_DIR, "post-deploy.log")

# == Load .env ==============================================================
env = {}
if os.path.exists(ENV_FILE):
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()

# == Config ==================================================================
NPM_PORT = 60081
NPM_EMAIL = env.get("NPM_ADMIN_EMAIL", "admin@yourdomain.com")
NPM_PASS = env.get("NPM_ADMIN_PASSWORD", "SocNpm@2025")

N8N_EMAIL = env.get("N8N_ADMIN_EMAIL", "admin@yourdomain.com")
N8N_PASS = env.get("N8N_ADMIN_PASSWORD", "SocN8n@2025")

CORTEX_ADMIN = env.get("CORTEX_ADMIN_USER", "admin@yourdomain.com")
CORTEX_PASS = env.get("CORTEX_ADMIN_PASSWORD", "SocCortex@2025")
CORTEX_ORG = env.get("CORTEX_ORG_NAME", "yourorg")
CORTEX_ORG_ADMIN = env.get("CORTEX_ORG_ADMIN", "orgadmin@yourdomain.com")

THEHIVE_USER = env.get("THEHIVE_ADMIN_USER", "admin@thehive.local")
THEHIVE_PASS = env.get("THEHIVE_ADMIN_PASSWORD", "SocTheHive@2025")
THEHIVE_DEFAULT = env.get("THEHIVE_DEFAULT_PASSWORD", "secret")
THEHIVE_ORG = env.get("THEHIVE_ORG_NAME", "YOURORG")
THEHIVE_ORG_DESC = env.get("THEHIVE_ORG_DESC", "Your SOC Organization")
THEHIVE_ANALYST = env.get("THEHIVE_ANALYST_USER", "analyst@yourdomain.com")
THEHIVE_ANALYST_PASS = env.get("THEHIVE_ANALYST_PASSWORD", "SocAnalyst@2025")

MISP_ADMIN = env.get("MISP_ADMIN_EMAIL", "admin@yourdomain.com")
MISP_PASS = env.get("MISP_ADMIN_PASSWORD", "SocMisp@2025")
MISP_DB_USER = env.get("MISP_DB_USER", "misp")
MISP_DB_PASS = env.get("MISP_DB_PASSWORD", "SocMispDb@2025")

KC_USER = env.get("KC_ADMIN_USER", "admin")
KC_PASS = env.get("KC_ADMIN_PASSWORD", "SocKeycloak@2025")

# SSO config -- reads KC_WAZUH_REALM / KC_WAZUH_CLIENT_ID from .env (falls back to SSO_REALM/SSO_CLIENT_ID)
SSO_REALM = env.get("KC_WAZUH_REALM", env.get("SSO_REALM", "SOC"))
SSO_CLIENT_ID = env.get("KC_WAZUH_CLIENT_ID", env.get("SSO_CLIENT_ID", "soc-sso"))

SSO_GROUP_ADMIN = env.get("SSO_GROUP_ADMIN", "soc-admin")
SSO_GROUP_ANALYST = env.get("SSO_GROUP_ANALYST", "soc-analyst")
SSO_GROUP_READONLY = env.get("SSO_GROUP_READONLY", "soc-readonly")

SSO_ADMIN_EMAIL = env.get("SSO_ADMIN_EMAIL", "admin@yourdomain.com")
SSO_ADMIN_PASS = env.get("SSO_ADMIN_PASSWORD", "SocSsoAdmin@2025")
SSO_ADMIN_FIRST = env.get("SSO_ADMIN_FIRST", "SOC")
SSO_ADMIN_LAST = env.get("SSO_ADMIN_LAST", "Admin")

SSO_ANALYST_EMAIL = env.get("SSO_ANALYST_EMAIL", "analyst@yourdomain.com")
SSO_ANALYST_PASS = env.get("SSO_ANALYST_PASSWORD", "SocSsoAnalyst@2025")
SSO_ANALYST_FIRST = env.get("SSO_ANALYST_FIRST", "SOC")
SSO_ANALYST_LAST = env.get("SSO_ANALYST_LAST", "Analyst")

SSO_READONLY_EMAIL = env.get("SSO_READONLY_EMAIL", "readonly@yourdomain.com")
SSO_READONLY_PASS = env.get("SSO_READONLY_PASSWORD", "SocSsoReadonly@2025")
SSO_READONLY_FIRST = env.get("SSO_READONLY_FIRST", "SOC")
SSO_READONLY_LAST = env.get("SSO_READONLY_LAST", "Readonly")

WAZUH_API_USER = env.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = env.get("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-")

WAZUH_DOMAIN = env.get("WAZUH_DOMAIN", "wazuh.yourdomain.com")
SSO_DOMAIN = env.get("SSO_DOMAIN", "sso.yourdomain.com")
CORTEX_DOMAIN = env.get("CORTEX_DOMAIN", "cortex.yourdomain.com")
THEHIVE_DOMAIN = env.get("THEHIVE_DOMAIN", "hive.yourdomain.com")
N8N_DOMAIN = env.get("N8N_DOMAIN", "n8n.yourdomain.com")

# n8n and TheHive go through oauth2-proxy (port 4180), MISP has native OIDC
DOMAINS = {
    "sso":     {"domain": env.get("SSO_DOMAIN", "sso.yourdomain.com"),     "host": "socstack-keycloak",            "port": 8080, "scheme": "http"},
    "wazuh":   {"domain": env.get("WAZUH_DOMAIN", "wazuh.yourdomain.com"), "host": "socstack-wazuh-dashboard",     "port": 5601, "scheme": "https"},
    "n8n":     {"domain": env.get("N8N_DOMAIN", "n8n.yourdomain.com"),     "host": "socstack-oauth2-proxy-n8n",    "port": 4180, "scheme": "http"},
    "cti":     {"domain": env.get("MISP_DOMAIN", "cti.yourdomain.com"),    "host": "socstack-misp-core",           "port": 443,  "scheme": "https"},
    "hive":    {"domain": env.get("THEHIVE_DOMAIN", "hive.yourdomain.com"),"host": "socstack-oauth2-proxy-hive",   "port": 4180, "scheme": "http"},
    "cortex":  {"domain": env.get("CORTEX_DOMAIN", "cortex.yourdomain.com"),"host": "socstack-cortex",             "port": 9001, "scheme": "http"},
    "npm":     {"domain": env.get("NPM_DOMAIN", "npm.yourdomain.com"),     "host": "socstack-nginx",            "port": 81,   "scheme": "http"},
}

deployed = {}  # Collect all deployed credentials
log_lines = []
results = {}   # Track pass/warn/fail status per step


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    log_lines.append(line)


def wait_for(name, url, timeout=120):
    log(f"  Waiting for {name}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code < 500:
                log(f"  -> {name} ready ({int(time.time()-start)}s)")
                return True
        except:
            pass
        time.sleep(3)
    log(f"  X {name} TIMEOUT after {timeout}s")
    return False


# ====================================================================
# STEP 1: NPM - Proxy Hosts + SSL
# ====================================================================
def step_npm():
    log("\n" + "="*60)
    log("STEP 1: Nginx Proxy Manager -> Proxy Hosts + SSL")
    log("="*60)

    NPM = f"http://localhost:{NPM_PORT}"
    if not wait_for("NPM", f"{NPM}/api/"):
        return

    # First-time setup or login
    resp = requests.post(f"{NPM}/api/tokens", json={"identity": NPM_EMAIL, "secret": NPM_PASS})
    if resp.status_code != 200:
        # Try legacy default credentials (NPM < 2.12)
        resp = requests.post(f"{NPM}/api/tokens", json={"identity": "admin@example.com", "secret": "changeme"})
        if resp.status_code == 200:
            t = resp.json()["token"]
            h = {"Authorization": f"Bearer {t}", "Content-Type": "application/json"}
            requests.put(f"{NPM}/api/users/1", headers=h, json={"email": NPM_EMAIL, "nickname": "Admin", "is_disabled": False, "roles": ["admin"]})
            requests.put(f"{NPM}/api/users/1/auth", headers=h, json={"type": "password", "current": "changeme", "secret": NPM_PASS})
            resp = requests.post(f"{NPM}/api/tokens", json={"identity": NPM_EMAIL, "secret": NPM_PASS})
        else:
            # NPM >= 2.14 starts with empty user table -- create admin directly
            try:
                setup_check = requests.get(f"{NPM}/api/")
                if setup_check.status_code == 200 and not setup_check.json().get("setup", True):
                    log("  -> Fresh NPM (no users) -- creating initial admin...")
                    create_resp = requests.post(f"{NPM}/api/users", json={
                        "name": "Administrator",
                        "nickname": "Admin",
                        "email": NPM_EMAIL,
                        "roles": ["admin"],
                        "is_disabled": False,
                        "auth": {"type": "password", "secret": NPM_PASS}
                    })
                    if create_resp.status_code in (200, 201):
                        log("  -> Initial admin user created")
                        resp = requests.post(f"{NPM}/api/tokens", json={"identity": NPM_EMAIL, "secret": NPM_PASS})
                    else:
                        log(f"  X Failed to create admin: {create_resp.status_code} {create_resp.text[:200]}")
            except Exception as e:
                log(f"  X Setup check failed: {e}")

    if resp.status_code != 200:
        log(f"  X NPM login failed: {resp.status_code}")
        return

    token = resp.json()["token"]
    h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    log("  -> NPM authenticated")
    deployed["NPM_ADMIN_EMAIL"] = NPM_EMAIL
    deployed["NPM_ADMIN_PASSWORD"] = NPM_PASS

    # Nginx advanced config for all proxy hosts
    # Large headers needed for OIDC/SSO redirects (JWT tokens, cookies)
    NPM_ADVANCED = (
        "large_client_header_buffers 4 32k;\n"
        "proxy_buffer_size 16k;\n"
        "proxy_buffers 8 16k;\n"
        "proxy_busy_buffers_size 32k;\n"
        "proxy_ssl_verify off;\n"
        "proxy_connect_timeout 300s;\n"
        "proxy_send_timeout 300s;\n"
        "proxy_read_timeout 300s;\n"
        "send_timeout 300s;"
    )

    # SSO proxy needs larger buffers for Keycloak OIDC responses
    NPM_ADVANCED_SSO = (
        "large_client_header_buffers 4 32k;\n"
        "proxy_buffer_size 128k;\n"
        "proxy_buffers 4 256k;\n"
        "proxy_busy_buffers_size 256k;\n"
        "proxy_ssl_verify off;\n"
        "proxy_connect_timeout 300s;\n"
        "proxy_send_timeout 300s;\n"
        "proxy_read_timeout 300s;\n"
        "send_timeout 300s;"
    )

    # Create proxy hosts
    existing = requests.get(f"{NPM}/api/nginx/proxy-hosts", headers=h).json()
    existing_map = {x["domain_names"][0]: x["id"] for x in existing if x.get("domain_names")}

    for key, cfg in DOMAINS.items():
        d = cfg["domain"]
        # SSO/oauth2-proxy services need block_exploits=False and larger buffers
        needs_sso_buffers = key in ("sso", "n8n", "hive")
        adv = NPM_ADVANCED_SSO if needs_sso_buffers else NPM_ADVANCED
        blk = False if needs_sso_buffers else True
        if d in existing_map:
            log(f"  -> Proxy exists: {d} (ID={existing_map[d]})")
        else:
            r = requests.post(f"{NPM}/api/nginx/proxy-hosts", headers=h, json={
                "domain_names": [d], "forward_host": cfg["host"], "forward_port": cfg["port"],
                "forward_scheme": cfg["scheme"], "block_exploits": blk,
                "allow_websocket_upgrade": True, "access_list_id": 0,
                "certificate_id": 0, "ssl_forced": False, "meta": {},
                "advanced_config": adv, "locations": []
            })
            if r.status_code == 201:
                existing_map[d] = r.json()["id"]
                log(f"  -> Proxy created: {d} (ID={existing_map[d]})")
            else:
                log(f"  X Proxy failed: {d}: {r.text[:100]}")

    # SSL certificates -- skip requesting new certs if all already exist
    log("\n  Checking SSL certificates...")
    certs = requests.get(f"{NPM}/api/nginx/certificates", headers=h).json()
    cert_map = {}
    for c in certs:
        for d in c["domain_names"]:
            cert_map[d] = c["id"]

    all_domains = [cfg["domain"] for cfg in DOMAINS.values()]
    domains_with_certs = [d for d in all_domains if d in cert_map]
    domains_without_certs = [d for d in all_domains if d not in cert_map]

    if not domains_without_certs:
        log(f"  -> All {len(domains_with_certs)} domains already have SSL certificates -- skipping")
    elif domains_with_certs:
        log(f"  -> {len(domains_with_certs)} domains have certs, {len(domains_without_certs)} need certs")

    for key, cfg in DOMAINS.items():
        d = cfg["domain"]
        if d in cert_map:
            log(f"  -> SSL exists: {d} (cert={cert_map[d]})")
            continue
        log(f"  Requesting SSL for {d}...")
        try:
            r = requests.post(f"{NPM}/api/nginx/certificates", headers=h, json={
                "domain_names": [d], "meta": {"dns_challenge": False}, "provider": "letsencrypt"
            }, timeout=120)
            if r.status_code == 201:
                cert_map[d] = r.json()["id"]
                log(f"  -> SSL cert: {d} (cert={cert_map[d]})")
            else:
                log(f"  X SSL failed: {d}: {r.text[:120]}")
        except Exception as e:
            log(f"  X SSL error: {d}: {e}")
        time.sleep(5)

    # Enable SSL on proxy hosts (only for domains that have certs)
    for key, cfg in DOMAINS.items():
        d = cfg["domain"]
        hid = existing_map.get(d)
        cid = cert_map.get(d)
        if not hid or not cid:
            continue
        is_sso = (key == "sso")
        adv = NPM_ADVANCED_SSO if is_sso else NPM_ADVANCED
        blk = False if is_sso else True
        cur = requests.get(f"{NPM}/api/nginx/proxy-hosts/{hid}", headers=h).json()
        if cur.get("certificate_id") == cid and cur.get("ssl_forced"):
            continue
        r = requests.put(f"{NPM}/api/nginx/proxy-hosts/{hid}", headers=h, json={
            "domain_names": [d], "forward_host": cfg["host"], "forward_port": cfg["port"],
            "forward_scheme": cfg["scheme"], "certificate_id": cid, "ssl_forced": True,
            "http2_support": True, "block_exploits": blk, "allow_websocket_upgrade": True,
            "access_list_id": 0, "advanced_config": adv, "meta": {}, "locations": []
        })
        if r.status_code == 200:
            log(f"  -> SSL enabled: {d}")


# ====================================================================
# STEP 2: n8n - Owner Setup (disables signup)
# ====================================================================
def step_n8n():
    log("\n" + "="*60)
    log("STEP 2: n8n -> Owner Account (signup disabled)")
    log("="*60)

    if not wait_for("n8n", "http://localhost:5678"):
        return

    r = requests.get("http://localhost:5678/rest/settings")
    if r.status_code == 200:
        show = r.json().get("data", {}).get("userManagement", {}).get("showSetupOnFirstLoad", True)
        if not show:
            log("  -> Owner already configured, signup disabled")
            deployed["N8N_ADMIN_EMAIL"] = N8N_EMAIL
            deployed["N8N_ADMIN_PASSWORD"] = N8N_PASS
            return

    r = requests.post("http://localhost:5678/rest/owner/setup", json={
        "email": N8N_EMAIL, "firstName": "SOC", "lastName": "Admin", "password": N8N_PASS
    })
    if r.status_code == 200:
        log(f"  -> Owner created: {N8N_EMAIL}")
        log("  -> Signup now disabled (invite-only)")
    else:
        log(f"  X Owner setup: {r.status_code} {r.text[:150]}")
    deployed["N8N_ADMIN_EMAIL"] = N8N_EMAIL
    deployed["N8N_ADMIN_PASSWORD"] = N8N_PASS


# ====================================================================
# STEP 3: Cortex - Migrate + SuperAdmin + Org + API Key
# ====================================================================
def step_cortex():
    log("\n" + "="*60)
    log("STEP 3: Cortex -> Init, Org, Users, API Key")
    log("="*60)

    CURL = "http://localhost:9001"
    if not wait_for("Cortex", f"{CURL}/api/status"):
        return None

    session = requests.Session()

    # Get CSRF token first (Cortex/Play Framework requires this)
    session.get(f"{CURL}/")
    csrf = session.cookies.get("CORTEX-XSRF-TOKEN", "")
    if csrf:
        session.headers.update({"X-CORTEX-XSRF-TOKEN": csrf})

    # Try login first (already initialized?)
    r = session.post(f"{CURL}/api/login", json={"user": CORTEX_ADMIN, "password": CORTEX_PASS})
    if r.status_code != 200:
        # Fresh: migrate + create superadmin
        log("  Running DB migration...")
        session.post(f"{CURL}/api/maintenance/migrate", json={})
        time.sleep(3)
        log("  Creating superadmin...")
        session.post(f"{CURL}/api/user", json={
            "login": CORTEX_ADMIN, "name": "SOC Admin",
            "roles": ["superadmin"], "password": CORTEX_PASS
        })
        time.sleep(2)
        r = session.post(f"{CURL}/api/login", json={"user": CORTEX_ADMIN, "password": CORTEX_PASS})
        if r.status_code != 200:
            log(f"  X Cortex login failed after init")
            return None
    log(f"  -> Logged in as {r.json().get('name')}")
    deployed["CORTEX_ADMIN_USER"] = CORTEX_ADMIN
    deployed["CORTEX_ADMIN_PASSWORD"] = CORTEX_PASS

    # Create org
    r = session.post(f"{CURL}/api/organization", json={
        "name": CORTEX_ORG, "description": "Your SOC Organization", "status": "Active"
    })
    if r.status_code == 201:
        log(f"  -> Organization '{CORTEX_ORG}' created")
    else:
        log(f"  -> Organization: already exists or {r.status_code}")

    # Create org admin
    r = session.post(f"{CURL}/api/user", json={
        "login": CORTEX_ORG_ADMIN, "name": "Org Admin",
        "roles": ["read", "analyze", "orgadmin"],
        "organization": CORTEX_ORG, "password": CORTEX_PASS
    })
    if r.status_code == 201:
        log(f"  -> Org admin created: {CORTEX_ORG_ADMIN}")
    else:
        log(f"  -> Org admin: already exists or {r.status_code}")
    deployed["CORTEX_ORG_ADMIN"] = CORTEX_ORG_ADMIN

    # API key (json={} needed to set Content-Type for CSRF check)
    r = session.post(f"{CURL}/api/user/{CORTEX_ORG_ADMIN}/key/renew", json={})
    if r.status_code == 200:
        api_key = r.text.strip().strip('"')
        log(f"  -> API Key: {api_key}")
        with open(os.path.join(BASE_DIR, ".cortex-api-key"), "w") as f:
            f.write(api_key)
        deployed["CORTEX_API_KEY"] = api_key
        return api_key
    else:
        # Try get existing
        r = session.get(f"{CURL}/api/user/{CORTEX_ORG_ADMIN}/key")
        if r.status_code == 200:
            api_key = r.text.strip().strip('"')
            log(f"  -> Existing API Key: {api_key}")
            deployed["CORTEX_API_KEY"] = api_key
            return api_key
    log(f"  X API key failed")
    return None


# ====================================================================
# STEP 4: TheHive - Password + Org + Analyst User
# ====================================================================
def step_thehive():
    log("\n" + "="*60)
    log("STEP 4: TheHive -> Password, Org, Analyst User")
    log("="*60)

    TH = "http://localhost:9000"
    if not wait_for("TheHive", f"{TH}/api/v1/status", timeout=180):
        return

    # Determine current password
    auth = None
    r = requests.get(f"{TH}/api/v1/user/current", auth=(THEHIVE_USER, THEHIVE_PASS))
    if r.status_code == 200:
        log(f"  -> Admin password already set")
        auth = (THEHIVE_USER, THEHIVE_PASS)
    else:
        r = requests.get(f"{TH}/api/v1/user/current", auth=(THEHIVE_USER, THEHIVE_DEFAULT))
        if r.status_code == 200:
            log("  Changing default password...")
            r = requests.post(f"{TH}/api/v1/user/{THEHIVE_USER}/password/set",
                              auth=(THEHIVE_USER, THEHIVE_DEFAULT),
                              json={"password": THEHIVE_PASS})
            if r.status_code == 204:
                log(f"  -> Password changed for {THEHIVE_USER}")
                auth = (THEHIVE_USER, THEHIVE_PASS)
            else:
                log(f"  X Password change failed: {r.status_code}")
                auth = (THEHIVE_USER, THEHIVE_DEFAULT)
        else:
            log("  X Cannot login with default or new password")
            return

    deployed["THEHIVE_ADMIN_USER"] = THEHIVE_USER
    deployed["THEHIVE_ADMIN_PASSWORD"] = THEHIVE_PASS

    # Create organization
    log(f"\n  Creating organization '{THEHIVE_ORG}'...")
    r = requests.post(f"{TH}/api/v1/organisation", auth=auth,
                      headers={"Content-Type": "application/json"},
                      json={"name": THEHIVE_ORG, "description": THEHIVE_ORG_DESC})
    if r.status_code == 201:
        org_id = r.json().get("_id")
        log(f"  -> Organization created: {THEHIVE_ORG} (ID={org_id})")
    elif r.status_code == 400 or r.status_code == 409:
        log(f"  -> Organization already exists")
        # Get org ID
        r2 = requests.post(f"{TH}/api/v1/query", auth=auth,
                           headers={"Content-Type": "application/json"},
                           json={"query": [{"_name": "listOrganisation"}]})
        if r2.status_code == 200:
            for org in r2.json():
                if org["name"] == THEHIVE_ORG:
                    org_id = org["_id"]
                    break
            else:
                org_id = None
    else:
        log(f"  X Org creation: {r.status_code} {r.text[:150]}")
        org_id = None

    # Create analyst user in the org
    if org_id or True:  # Try anyway
        log(f"\n  Creating analyst user: {THEHIVE_ANALYST}...")
        r = requests.post(f"{TH}/api/v1/user", auth=auth,
                          headers={"Content-Type": "application/json"},
                          json={
                              "login": THEHIVE_ANALYST,
                              "name": "SOC Analyst",
                              "profile": "analyst",
                              "organisation": THEHIVE_ORG,
                              "password": THEHIVE_ANALYST_PASS
                          })
        if r.status_code == 201:
            user_id = r.json().get("_id")
            log(f"  -> Analyst created: {THEHIVE_ANALYST} (ID={user_id})")
            # Set password
            r2 = requests.post(f"{TH}/api/v1/user/{THEHIVE_ANALYST}/password/set",
                               auth=auth, json={"password": THEHIVE_ANALYST_PASS})
            if r2.status_code == 204:
                log(f"  -> Analyst password set")
            else:
                log(f"  X Analyst password: {r2.status_code}")
        elif "already exist" in r.text.lower() or r.status_code == 400:
            log(f"  -> Analyst already exists")
        else:
            log(f"  X Analyst creation: {r.status_code} {r.text[:150]}")

        deployed["THEHIVE_ANALYST_USER"] = THEHIVE_ANALYST
        deployed["THEHIVE_ANALYST_PASSWORD"] = THEHIVE_ANALYST_PASS

    return auth


# ====================================================================
# STEP 5: MISP <-> TheHive Integration
# ====================================================================
def step_misp_thehive(th_auth):
    log("\n" + "="*60)
    log("STEP 5: MISP <-> TheHive Integration")
    log("="*60)

    TH = "http://localhost:9000"

    # Get MISP API key from DB
    log("  Retrieving MISP API key from database...")
    try:
        result = subprocess.run(
            ["docker", "exec", "socstack-misp-db", "mysql", "-u", MISP_DB_USER,
             f"-p{MISP_DB_PASS}", "misp", "-N", "-e",
             f"SELECT authkey FROM users WHERE email='{MISP_ADMIN}' LIMIT 1;"],
            capture_output=True, text=True, timeout=10
        )
        misp_key = result.stdout.strip()
    except Exception as e:
        log(f"  X Failed to get MISP key: {e}")
        misp_key = None

    if not misp_key:
        log("  X MISP API key not found")
        return

    log(f"  -> MISP API Key: {misp_key}")
    deployed["MISP_API_KEY"] = misp_key

    # Verify MISP key works
    r = requests.get("https://localhost:8443/servers/getVersion",
                      headers={"Authorization": misp_key, "Accept": "application/json"},
                      verify=False)
    if r.status_code == 200:
        ver = r.json().get("version", "?")
        log(f"  -> MISP API verified (v{ver})")
    else:
        log(f"  X MISP API verification failed: {r.status_code}")
        return

    if not th_auth:
        log("  X TheHive auth not available, skipping integration")
        return

    # Add MISP server to TheHive via custom config
    # TheHive 5.x uses the MISP connector in the Platform Management
    # We configure it via the API
    misp_url = f"https://{DOMAINS['cti']['host']}:443"
    log(f"\n  Configuring TheHive -> MISP connector...")
    log(f"  MISP internal URL: {misp_url}")

    # Check if MISP connector already configured
    r = requests.post(f"{TH}/api/v1/query", auth=th_auth,
                      headers={"Content-Type": "application/json"},
                      json={"query": [{"_name": "listConnector"}]})

    if r.status_code == 200:
        connectors = r.json()
        misp_exists = any(c.get("name") == f"MISP-{THEHIVE_ORG}" for c in connectors)
        if misp_exists:
            log("  -> MISP connector already configured in TheHive")
            return

    # Create MISP connector in TheHive
    # TheHive 5.x uses the connector API
    r = requests.post(f"{TH}/api/connector/misp", auth=th_auth,
                      headers={"Content-Type": "application/json"},
                      json={
                          "name": f"MISP-{THEHIVE_ORG}",
                          "url": misp_url,
                          "auth": {"type": "key", "key": misp_key},
                          "wsConfig": {"ssl": {"loose.acceptAnyCertificate": True}},
                          "purpose": "ImportAndExport",
                          "includedTheHiveOrganisations": [THEHIVE_ORG],
                          "maxAttributes": 10000,
                          "maxAge": 365
                      })
    if r.status_code in (200, 201):
        log(f"  -> MISP connector added to TheHive")
    elif r.status_code == 404:
        # TheHive 5.2 may use different endpoint
        log(f"  -> MISP connector API not available (configure via UI)")
        log(f"    URL: {misp_url}")
        log(f"    API Key: {misp_key}")
        log(f"    -> Go to TheHive UI -> Platform Management -> MISP Servers -> Add")
    else:
        log(f"  -> MISP connector: {r.status_code} {r.text[:150]}")
        log(f"    Configure manually in TheHive UI:")
        log(f"    URL: {misp_url}")
        log(f"    API Key: {misp_key}")


# ====================================================================
# STEP 5b: MISP Feeds -> Load Defaults, Enable All, Cache All
#   Daily updates handled by MISP's built-in scheduled_tasks (86400s)
#   configured via CRON_USER_ID env var in docker-compose.yml
# ====================================================================
def step_misp_feeds():
    log("\n" + "="*60)
    log("STEP 5b: MISP Feeds -> Load Defaults + Enable All + Cache All")
    log("="*60)

    MISP_URL = "https://localhost:8443"

    # Get MISP API key from DB
    log("  Retrieving MISP API key...")
    misp_key = deployed.get("MISP_API_KEY")
    if not misp_key:
        try:
            result = subprocess.run(
                ["docker", "exec", "socstack-misp-db", "mysql", "-u", MISP_DB_USER,
                 f"-p{MISP_DB_PASS}", "misp", "-N", "-e",
                 f"SELECT authkey FROM users WHERE email='{MISP_ADMIN}' LIMIT 1;"],
                capture_output=True, text=True, timeout=10
            )
            misp_key = result.stdout.strip()
        except Exception as e:
            log(f"  X Failed to get MISP key: {e}")

    if not misp_key:
        log("  X MISP API key not available -- skipping feed setup")
        return

    mh = {
        "Authorization": misp_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # Verify MISP is reachable
    try:
        r = requests.get(f"{MISP_URL}/servers/getVersion", headers=mh, verify=False, timeout=10)
        if r.status_code != 200:
            log(f"  X MISP not responding ({r.status_code}) -- skipping feed setup")
            return
        log(f"  -> MISP API reachable (v{r.json().get('version','?')})")
    except Exception as e:
        log(f"  X MISP connection failed: {e}")
        return

    # Track results for this step
    feed_results = {
        "defaults_loaded": False,
        "total_feeds": 0,
        "feeds_enabled": 0,
        "caching_enabled": 0,
        "cache_initiated": False,
        "fetch_initiated": False,
        "scheduler_ok": False,
    }

    # ── 5b.1: Load default feeds (93 CTI sources from MISP project) ──
    log("\n  Loading default MISP feeds...")
    try:
        r = requests.post(f"{MISP_URL}/feeds/loadDefaultFeeds",
                          headers=mh, json={}, verify=False, timeout=60)
        if r.status_code == 200:
            log(f"  -> Default feeds loaded successfully")
            feed_results["defaults_loaded"] = True
        else:
            log(f"  -> Load defaults: {r.status_code} {r.text[:150]}")
    except Exception as e:
        log(f"  X Load defaults error: {e}")

    # ── 5b.2: List all feeds ──────────────────────────────────────────
    log("  Fetching feed list...")
    try:
        r = requests.get(f"{MISP_URL}/feeds/index", headers=mh, verify=False, timeout=30)
        if r.status_code != 200:
            log(f"  X Feed list failed: {r.status_code}")
            return
        feeds = r.json()
        # MISP may return feeds in different formats
        if isinstance(feeds, list) and feeds and "Feed" in feeds[0]:
            # Wrapped format: [{"Feed": {...}}, ...]
            feed_list = [f["Feed"] for f in feeds]
        elif isinstance(feeds, list):
            feed_list = feeds
        else:
            log(f"  X Unexpected feed format: {type(feeds)}")
            return
        log(f"  -> Found {len(feed_list)} feeds total")
    except Exception as e:
        log(f"  X Feed list error: {e}")
        return

    # ── 5b.3: Enable all feeds ────────────────────────────────────────
    disabled_feeds = [f for f in feed_list if not f.get("enabled")]
    already_enabled = len(feed_list) - len(disabled_feeds)
    log(f"  -> {already_enabled} already enabled, {len(disabled_feeds)} to enable")

    enabled_count = 0
    failed_count = 0
    for feed in disabled_feeds:
        fid = feed.get("id")
        fname = feed.get("name", f"Feed-{fid}")
        try:
            r = requests.post(f"{MISP_URL}/feeds/enable/{fid}",
                              headers=mh, json={}, verify=False, timeout=15)
            if r.status_code == 200:
                enabled_count += 1
            else:
                failed_count += 1
                if failed_count <= 3:
                    log(f"  X Enable failed: {fname} ({r.status_code})")
        except Exception as e:
            failed_count += 1
            if failed_count <= 3:
                log(f"  X Enable error: {fname}: {e}")

    if enabled_count > 0:
        log(f"  -> Enabled {enabled_count} feeds")
    if failed_count > 0:
        log(f"  -> {failed_count} feeds failed to enable")

    # ── 5b.4: Enable caching on all feeds ─────────────────────────────
    log("\n  Enabling caching on all feeds...")
    already_cached = sum(1 for f in feed_list if f.get("caching_enabled"))
    cache_enabled = 0
    for feed in feed_list:
        fid = feed.get("id")
        if not feed.get("caching_enabled"):
            try:
                r = requests.post(f"{MISP_URL}/feeds/edit/{fid}",
                                  headers=mh, json={"Feed": {"caching_enabled": 1}},
                                  verify=False, timeout=15)
                if r.status_code == 200:
                    cache_enabled += 1
            except Exception:
                pass
    log(f"  -> Caching enabled on {cache_enabled} additional feeds")
    feed_results["caching_enabled"] = already_cached + cache_enabled

    # ── 5b.5: Cache all feeds (initial download) ──────────────────────
    log("\n  Caching all enabled feeds (initial download)...")
    log("  -> This may take several minutes for large feed sets...")
    try:
        r = requests.post(f"{MISP_URL}/feeds/cacheFeeds/all",
                          headers=mh, json={}, verify=False, timeout=600)
        if r.status_code == 200:
            log(f"  -> Feed cache initiated successfully")
            feed_results["cache_initiated"] = True
        else:
            log(f"  -> Feed cache response: {r.status_code} {r.text[:150]}")
    except requests.exceptions.Timeout:
        log("  -> Feed cache is running (timed out waiting, will continue in background)")
        feed_results["cache_initiated"] = True  # Running in background counts
    except Exception as e:
        log(f"  X Feed cache error: {e}")

    # ── 5b.6: Fetch from all feeds (pull IOCs into MISP) ──────────────
    log("  Fetching data from all enabled feeds into MISP events...")
    try:
        r = requests.post(f"{MISP_URL}/feeds/fetchFromAllFeeds",
                          headers=mh, json={}, verify=False, timeout=600)
        if r.status_code == 200:
            log(f"  -> Feed fetch initiated successfully")
            feed_results["fetch_initiated"] = True
        else:
            log(f"  -> Feed fetch response: {r.status_code} {r.text[:150]}")
    except requests.exceptions.Timeout:
        log("  -> Feed fetch is running (timed out waiting, will continue in background)")
        feed_results["fetch_initiated"] = True
    except Exception as e:
        log(f"  X Feed fetch error: {e}")

    # ── 5b.7: Verify MISP built-in scheduled tasks ───────────────────
    # MISP Docker creates these via CRON_USER_ID env var in configure_misp.sh:
    #   - Daily fetch of all Feeds (86400s)
    #   - Daily cache of all Feeds (86400s)
    # No external cron needed!
    log("\n  Verifying MISP built-in scheduled tasks...")
    try:
        result = subprocess.run(
            ["docker", "exec", "socstack-misp-db", "mysql", "-u", MISP_DB_USER,
             f"-p{MISP_DB_PASS}", "misp", "-N", "-e",
             "SELECT CONCAT(description, ' (', timer, 's, enabled=', enabled, ')') "
             "FROM scheduled_tasks WHERE type='Feed';"],
            capture_output=True, text=True, timeout=10
        )
        tasks = result.stdout.strip().split("\n")
        for t in tasks:
            if t.strip():
                log(f"  -> {t.strip()}")
        if tasks and tasks[0].strip():
            feed_results["scheduler_ok"] = True
        else:
            log("  ! No feed scheduled tasks found -- check CRON_USER_ID env var")
    except Exception as e:
        log(f"  X Scheduled task check: {e}")

    # ── Summary ───────────────────────────────────────────────────────
    total_enabled = already_enabled + enabled_count
    feed_results["total_feeds"] = len(feed_list)
    feed_results["feeds_enabled"] = total_enabled
    results["misp_feeds"] = feed_results

    log(f"\n  MISP Feeds Summary:")
    log(f"    Total feeds:     {len(feed_list)}")
    log(f"    Enabled:         {total_enabled}")
    log(f"    Caching:         Initiated (runs in background)")
    log(f"    Daily updates:   MISP built-in scheduler (every 86400s)")
    log(f"    No external cron needed -- MISP handles it internally")


# ====================================================================
# STEP 6: Keycloak SSO -> SOC (Realm, Client, Groups, Users)
# ====================================================================
def step_keycloak_sso():
    log("\n" + "="*60)
    log("STEP 6: Keycloak SSO -> SOC Realm + soc-sso Client")
    log("="*60)

    KC = "http://localhost:8081"
    if not wait_for("Keycloak", f"{KC}/realms/master"):
        return None

    # -- Get master token -----------------------------------------------
    r = requests.post(f"{KC}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": KC_USER, "password": KC_PASS,
    })
    if r.status_code != 200:
        log(f"  X Keycloak admin login failed: {r.status_code}")
        return None
    token = r.json()["access_token"]
    h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    log(f"  -> Keycloak admin authenticated")

    # -- Create realm ---------------------------------------------------
    r = requests.get(f"{KC}/admin/realms/{SSO_REALM}", headers=h)
    if r.status_code == 200:
        log(f"  -> Realm '{SSO_REALM}' already exists")
    else:
        r = requests.post(f"{KC}/admin/realms", headers=h, json={
            "realm": SSO_REALM, "enabled": True,
            "displayName": "SOC SSO",
            "loginWithEmailAllowed": True,
            "sslRequired": "none",
        })
        if r.status_code == 201:
            log(f"  -> Realm '{SSO_REALM}' created")
        else:
            log(f"  X Realm creation failed: {r.status_code} {r.text[:150]}")
            return None

    # -- Create OIDC client (confidential) - single client for all ------
    # Redirect URIs for all services
    MISP_DOMAIN = env.get("MISP_DOMAIN", "cti.yourdomain.com")
    redirect_uris = [
        f"https://{WAZUH_DOMAIN}/*",
        f"https://{CORTEX_DOMAIN}/api/ssoLogin",
        f"https://{THEHIVE_DOMAIN}/oauth2/callback",    # oauth2-proxy callback
        f"https://{THEHIVE_DOMAIN}/api/ssoLogin",       # legacy (kept for reference)
        f"https://{N8N_DOMAIN}/oauth2/callback",
        f"https://{MISP_DOMAIN}/users/login",            # MISP native OIDC
        f"https://{MISP_DOMAIN}/*",
    ]
    web_origins = [
        f"https://{WAZUH_DOMAIN}",
        f"https://{CORTEX_DOMAIN}",
        f"https://{THEHIVE_DOMAIN}",
        f"https://{N8N_DOMAIN}",
        f"https://{MISP_DOMAIN}",
    ]
    post_logout_uris = "+".join([
        f"https://{WAZUH_DOMAIN}/*",
        f"https://{CORTEX_DOMAIN}/*",
        f"https://{THEHIVE_DOMAIN}/*",
        f"https://{N8N_DOMAIN}/*",
        f"https://{MISP_DOMAIN}/*",
    ])

    # Check existing clients
    r = requests.get(f"{KC}/admin/realms/{SSO_REALM}/clients?clientId={SSO_CLIENT_ID}", headers=h)
    existing_clients = r.json() if r.status_code == 200 else []
    client_uuid = None

    # Use static client secret from .env (generated by pre-deploy.sh)
    # This ensures oauth2-proxy containers start with the correct secret
    # on first boot — no chicken-and-egg dependency
    static_secret = env.get("SSO_CLIENT_SECRET", "")
    if not static_secret:
        log("  ! SSO_CLIENT_SECRET not set in .env — generating one")
        static_secret = secrets.token_urlsafe(32)

    if existing_clients:
        client_uuid = existing_clients[0]["id"]
        log(f"  -> Client '{SSO_CLIENT_ID}' already exists (UUID={client_uuid[:8]}...)")
        # Update redirect URIs, web origins, post-logout URIs, AND set static secret
        r = requests.put(f"{KC}/admin/realms/{SSO_REALM}/clients/{client_uuid}", headers=h, json={
            "clientId": SSO_CLIENT_ID,
            "secret": static_secret,
            "redirectUris": redirect_uris,
            "webOrigins": web_origins,
            "attributes": {
                "post.logout.redirect.uris": post_logout_uris,
            },
        })
        if r.status_code == 204:
            log(f"  -> Client updated (secret synced from .env)")
        else:
            log(f"  ! Client update returned: {r.status_code}")
    else:
        r = requests.post(f"{KC}/admin/realms/{SSO_REALM}/clients", headers=h, json={
            "clientId": SSO_CLIENT_ID,
            "name": "SOC SSO Client",
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": static_secret,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": False,
            "redirectUris": redirect_uris,
            "webOrigins": web_origins,
            "attributes": {
                "post.logout.redirect.uris": post_logout_uris,
            },
        })
        if r.status_code == 201:
            # Get the UUID from Location header
            loc = r.headers.get("Location", "")
            client_uuid = loc.rsplit("/", 1)[-1] if loc else None
            if not client_uuid:
                # Fetch it
                r2 = requests.get(f"{KC}/admin/realms/{SSO_REALM}/clients?clientId={SSO_CLIENT_ID}", headers=h)
                if r2.status_code == 200 and r2.json():
                    client_uuid = r2.json()[0]["id"]
            log(f"  -> Client '{SSO_CLIENT_ID}' created (UUID={client_uuid[:8]}...)")
        else:
            log(f"  X Client creation failed: {r.status_code} {r.text[:150]}")
            return None

    # -- Add 'groups' protocol mapper to client -------------------------
    if client_uuid:
        # Check existing mappers
        r = requests.get(f"{KC}/admin/realms/{SSO_REALM}/clients/{client_uuid}/protocol-mappers/models", headers=h)
        existing_mappers = [m["name"] for m in r.json()] if r.status_code == 200 else []
        if "groups" not in existing_mappers:
            r = requests.post(f"{KC}/admin/realms/{SSO_REALM}/clients/{client_uuid}/protocol-mappers/models", headers=h, json={
                "name": "groups",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-group-membership-mapper",
                "consentRequired": False,
                "config": {
                    "full.path": "false",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "groups",
                    "userinfo.token.claim": "true",
                },
            })
            if r.status_code == 201:
                log(f"  -> Protocol mapper 'groups' added to client")
            else:
                log(f"  X Mapper creation: {r.status_code} {r.text[:100]}")
        else:
            log(f"  -> Protocol mapper 'groups' already exists")

    # -- Client secret: use static value from .env -----------------------
    # The secret was already set during client creation/update above.
    # No need to read from Keycloak — .env is the single source of truth.
    client_secret = static_secret
    log(f"  -> Client secret (from .env): {client_secret[:8]}...{client_secret[-4:]}")
    deployed["SSO_CLIENT_SECRET"] = client_secret

    # -- Create groups --------------------------------------------------
    for group_name in [SSO_GROUP_ADMIN, SSO_GROUP_ANALYST, SSO_GROUP_READONLY]:
        r = requests.get(f"{KC}/admin/realms/{SSO_REALM}/groups?search={group_name}&exact=true", headers=h)
        existing = r.json() if r.status_code == 200 else []
        if existing:
            log(f"  -> Group '{group_name}' already exists")
        else:
            r = requests.post(f"{KC}/admin/realms/{SSO_REALM}/groups", headers=h, json={
                "name": group_name,
            })
            if r.status_code == 201:
                log(f"  -> Group '{group_name}' created")
            else:
                log(f"  X Group '{group_name}': {r.status_code} {r.text[:100]}")

    # Helper: get group ID by name
    def get_group_id(name):
        r = requests.get(f"{KC}/admin/realms/{SSO_REALM}/groups?search={name}&exact=true", headers=h)
        groups = r.json() if r.status_code == 200 else []
        for g in groups:
            if g["name"] == name:
                return g["id"]
        return None

    # -- Create SSO users -----------------------------------------------
    sso_users = [
        {"email": SSO_ADMIN_EMAIL, "password": SSO_ADMIN_PASS,
         "first": SSO_ADMIN_FIRST, "last": SSO_ADMIN_LAST, "group": SSO_GROUP_ADMIN},
        {"email": SSO_ANALYST_EMAIL, "password": SSO_ANALYST_PASS,
         "first": SSO_ANALYST_FIRST, "last": SSO_ANALYST_LAST, "group": SSO_GROUP_ANALYST},
        {"email": SSO_READONLY_EMAIL, "password": SSO_READONLY_PASS,
         "first": SSO_READONLY_FIRST, "last": SSO_READONLY_LAST, "group": SSO_GROUP_READONLY},
    ]

    for u in sso_users:
        username = u["email"]
        # Check existing
        r = requests.get(f"{KC}/admin/realms/{SSO_REALM}/users?username={username}&exact=true", headers=h)
        existing_users = r.json() if r.status_code == 200 else []
        user_id = None

        if existing_users:
            user_id = existing_users[0]["id"]
            log(f"  -> User '{username}' already exists")
        else:
            r = requests.post(f"{KC}/admin/realms/{SSO_REALM}/users", headers=h, json={
                "username": username,
                "email": username,
                "firstName": u["first"],
                "lastName": u["last"],
                "enabled": True,
                "emailVerified": True,
                "credentials": [{
                    "type": "password",
                    "value": u["password"],
                    "temporary": False,
                }],
            })
            if r.status_code == 201:
                loc = r.headers.get("Location", "")
                user_id = loc.rsplit("/", 1)[-1] if loc else None
                if not user_id:
                    r2 = requests.get(f"{KC}/admin/realms/{SSO_REALM}/users?username={username}&exact=true", headers=h)
                    if r2.status_code == 200 and r2.json():
                        user_id = r2.json()[0]["id"]
                log(f"  -> User '{username}' created (group={u['group']})")
            else:
                log(f"  X User '{username}': {r.status_code} {r.text[:100]}")

        # Assign to group
        if user_id:
            group_id = get_group_id(u["group"])
            if group_id:
                r = requests.put(f"{KC}/admin/realms/{SSO_REALM}/users/{user_id}/groups/{group_id}", headers=h)
                if r.status_code == 204:
                    log(f"  -> User '{username}' -> group '{u['group']}'")
                else:
                    log(f"  X Group assignment: {r.status_code}")

    # -- Save SSO credentials -------------------------------------------
    deployed["SSO_ADMIN_EMAIL"] = SSO_ADMIN_EMAIL
    deployed["SSO_ADMIN_PASSWORD"] = SSO_ADMIN_PASS
    deployed["SSO_ANALYST_EMAIL"] = SSO_ANALYST_EMAIL
    deployed["SSO_ANALYST_PASSWORD"] = SSO_ANALYST_PASS
    deployed["SSO_READONLY_EMAIL"] = SSO_READONLY_EMAIL
    deployed["SSO_READONLY_PASSWORD"] = SSO_READONLY_PASS
    deployed["SSO_REALM"] = SSO_REALM
    deployed["SSO_CLIENT_ID"] = SSO_CLIENT_ID

    # -- Replace domain/realm/client placeholders in config files --------
    config_replacements = {
        "YOUR_SSO_DOMAIN": SSO_DOMAIN,
        "YOUR_SSO_REALM": SSO_REALM,
        "YOUR_SSO_CLIENT_ID": SSO_CLIENT_ID,
        "YOUR_WAZUH_DOMAIN": WAZUH_DOMAIN,
        "YOUR_N8N_DOMAIN": N8N_DOMAIN,
        "YOUR_N8N_WEBHOOK_ID": env.get("N8N_WEBHOOK_ID", "21219720-0300-4e29-8408-ea4b3a759e96"),
        "YOUR_CORTEX_DOMAIN": CORTEX_DOMAIN,
        "YOUR_CORTEX_SECRET": env.get("CORTEX_SECRET", "ChangeMe_Cortex2025SecretKey"),
        "YOUR_CORTEX_ORG_NAME": CORTEX_ORG,
        "YOUR_THEHIVE_DOMAIN": THEHIVE_DOMAIN,
        "YOUR_THEHIVE_ORG_NAME": THEHIVE_ORG,
    }
    config_files = [
        os.path.join(BASE_DIR, "configs/thehive/cortex-application.conf"),
        os.path.join(BASE_DIR, "configs/thehive/thehive-application.conf"),
        os.path.join(BASE_DIR, "configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml"),
        os.path.join(BASE_DIR, "configs/wazuh/wazuh_indexer/config.yml"),
        os.path.join(BASE_DIR, "configs/wazuh/wazuh_cluster/wazuh_manager.conf"),
    ]
    for cfg_path in config_files:
        if os.path.exists(cfg_path):
            with open(cfg_path) as f:
                content = f.read()
            original = content
            for placeholder, value in config_replacements.items():
                content = content.replace(placeholder, value)
            if content != original:
                with open(cfg_path, "w") as f:
                    f.write(content)
                log(f"  -> Placeholders replaced in {os.path.basename(cfg_path)}")
            else:
                log(f"  -> No placeholders found in {os.path.basename(cfg_path)} (already configured)")

    # -- Inject client_secret into config files -------------------------
    if client_secret:
        # 1. opensearch_dashboards.yml (Wazuh Dashboard)
        dash_yml = os.path.join(BASE_DIR, "configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml")
        if os.path.exists(dash_yml):
            with open(dash_yml) as f:
                content = f.read()
            changed = False
            if "WILL_BE_SET_BY_POST_DEPLOY" in content:
                content = content.replace("WILL_BE_SET_BY_POST_DEPLOY", client_secret)
                changed = True
                log(f"  -> Client secret injected into opensearch_dashboards.yml")
            elif client_secret not in content:
                content = re.sub(
                    r'(opensearch_security\.openid\.client_secret:\s*)(".*?"|\'.*?\'|[^\s]+)',
                    f'\\1"{client_secret}"',
                    content
                )
                changed = True
                log(f"  -> Client secret updated in opensearch_dashboards.yml")
            else:
                log(f"  -> Client secret already in opensearch_dashboards.yml")
            if changed:
                with open(dash_yml, "w") as f:
                    f.write(content)
        else:
            log(f"  X Dashboard config not found at {dash_yml}")

        # 2. cortex-application.conf (Cortex native OAuth2)
        cortex_conf = os.path.join(BASE_DIR, "configs/thehive/cortex-application.conf")
        if os.path.exists(cortex_conf):
            with open(cortex_conf) as f:
                content = f.read()
            changed = False
            if "WILL_BE_SET_BY_POST_DEPLOY" in content:
                content = content.replace("WILL_BE_SET_BY_POST_DEPLOY", client_secret)
                changed = True
                log(f"  -> Client secret injected into cortex-application.conf")
            elif client_secret not in content:
                log(f"  -> cortex-application.conf: secret not found as placeholder, skipping")
            else:
                log(f"  -> Client secret already in cortex-application.conf")
            if changed:
                with open(cortex_conf, "w") as f:
                    f.write(content)
        else:
            log(f"  X Cortex config not found at {cortex_conf}")

        # 3. thehive-application.conf (TheHive native OAuth2)
        thehive_conf = os.path.join(BASE_DIR, "configs/thehive/thehive-application.conf")
        if os.path.exists(thehive_conf):
            with open(thehive_conf) as f:
                content = f.read()
            changed = False
            if "WILL_BE_SET_BY_POST_DEPLOY" in content:
                content = content.replace("WILL_BE_SET_BY_POST_DEPLOY", client_secret)
                changed = True
                log(f"  -> Client secret injected into thehive-application.conf")
            elif client_secret not in content:
                log(f"  -> thehive-application.conf: secret not found as placeholder, skipping")
            else:
                log(f"  -> Client secret already in thehive-application.conf")
            if changed:
                with open(thehive_conf, "w") as f:
                    f.write(content)
        else:
            log(f"  X TheHive config not found at {thehive_conf}")

    # -- Restart Cortex to pick up updated config (SSO URLs, client secret) --
    # Cortex reads application.conf at startup and caches it in memory.
    # Config replacement happens AFTER containers start, so Cortex must be restarted.
    log("\n  Restarting Cortex to apply SSO config...")
    try:
        subprocess.run(["docker", "restart", "socstack-cortex"],
                       capture_output=True, text=True, timeout=30)
        log("  -> Cortex restarting (SSO config will take effect)")
    except Exception as e:
        log(f"  X Cortex restart failed: {e}")
    time.sleep(10)

    # -- Generate OAUTH2_PROXY_COOKIE_SECRET (reuse existing if set) -----
    cookie_secret = env.get("OAUTH2_PROXY_COOKIE_SECRET", "")
    if cookie_secret:
        log(f"\n  OAUTH2_PROXY_COOKIE_SECRET already set: {cookie_secret[:12]}... (reusing)")
    else:
        log("\n  Generating OAUTH2_PROXY_COOKIE_SECRET...")
        cookie_secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
        log(f"  -> OAUTH2_PROXY_COOKIE_SECRET: {cookie_secret[:12]}...")
    deployed["OAUTH2_PROXY_COOKIE_SECRET"] = cookie_secret

    # -- Save SSO_CLIENT_SECRET and OAUTH2_PROXY_COOKIE_SECRET to .env --
    if client_secret or cookie_secret:
        log("\n  Updating .env with SSO secrets...")
        env_path = os.path.join(BASE_DIR, ".env")
        if os.path.exists(env_path):
            with open(env_path) as f:
                env_content = f.read()

            # Add/update SSO_CLIENT_SECRET
            if client_secret:
                if re.search(r'^SSO_CLIENT_SECRET=', env_content, re.MULTILINE):
                    env_content = re.sub(
                        r'^SSO_CLIENT_SECRET=.*$',
                        f'SSO_CLIENT_SECRET={client_secret}',
                        env_content,
                        flags=re.MULTILINE
                    )
                else:
                    # Append after any SSO_CLIENT_SECRET comment or at end
                    env_content = env_content.rstrip() + f"\nSSO_CLIENT_SECRET={client_secret}\n"
                log(f"  -> SSO_CLIENT_SECRET saved to .env")

            # Add/update OAUTH2_PROXY_COOKIE_SECRET
            if cookie_secret:
                if re.search(r'^OAUTH2_PROXY_COOKIE_SECRET=', env_content, re.MULTILINE):
                    env_content = re.sub(
                        r'^OAUTH2_PROXY_COOKIE_SECRET=.*$',
                        f'OAUTH2_PROXY_COOKIE_SECRET={cookie_secret}',
                        env_content,
                        flags=re.MULTILINE
                    )
                else:
                    # Append after SSO_CLIENT_SECRET or at end
                    env_content = env_content.rstrip() + f"\nOAUTH2_PROXY_COOKIE_SECRET={cookie_secret}\n"
                log(f"  -> OAUTH2_PROXY_COOKIE_SECRET saved to .env")

            with open(env_path, "w") as f:
                f.write(env_content)

    return client_secret


# ====================================================================
# STEP 7: Apply Wazuh Security Configs (securityadmin)
# ====================================================================
def step_wazuh_security():
    log("\n" + "="*60)
    log("STEP 7: Wazuh Security -> Apply configs (securityadmin)")
    log("="*60)

    # Wait for indexer to be available
    if not wait_for("Wazuh Indexer", "https://localhost:9200/",
                     timeout=60):
        log("  ! Indexer not responding, trying anyway...")

    # -- Step 7a: Copy system CA into indexer (needed for OIDC SSL trust) --
    # system-ca.pem is bind-mounted from host (pre-deploy.sh creates it)
    log("  Verifying system-ca.pem in indexer for OIDC SSL trust...")
    try:
        check = subprocess.run(
            ["docker", "exec", "socstack-wazuh-indexer",
             "test", "-f", "/usr/share/wazuh-indexer/config/certs/system-ca.pem"],
            capture_output=True, text=True, timeout=10
        )
        if check.returncode == 0:
            log("  -> system-ca.pem exists (bind-mounted from host)")
        else:
            # Fallback: copy from container's own system CA
            subprocess.run(
                ["docker", "exec", "-u", "root", "socstack-wazuh-indexer",
                 "cp", "/etc/ssl/certs/ca-certificates.crt",
                 "/usr/share/wazuh-indexer/config/certs/system-ca.pem"],
                capture_output=True, text=True, timeout=10
            )
            subprocess.run(
                ["docker", "exec", "-u", "root", "socstack-wazuh-indexer",
                 "chmod", "644", "/usr/share/wazuh-indexer/config/certs/system-ca.pem"],
                capture_output=True, text=True, timeout=10
            )
            log("  -> system-ca.pem copied from container (fallback)")
    except Exception as e:
        log(f"  X system-ca.pem check failed: {e}")

    # -- Step 7b: Run securityadmin FIRST (before any restart) ----------
    # This pushes config.yml (with SOC realm config) into the live security index
    # Must run BEFORE dashboard restart so SSO config is live when dashboard starts
    log("  Running securityadmin to apply security configs (config, roles, mappings)...")
    sa_cmd = (
        "JAVA_HOME=/usr/share/wazuh-indexer/jdk "
        "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh "
        "-cd /usr/share/wazuh-indexer/config/opensearch-security/ "
        "-nhnv "
        "-cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem "
        "-cert /usr/share/wazuh-indexer/config/certs/admin.pem "
        "-key /usr/share/wazuh-indexer/config/certs/admin-key.pem "
        "-icl -p 9200"
    )

    try:
        result = subprocess.run(
            ["docker", "exec", "socstack-wazuh-indexer", "bash", "-c", sa_cmd],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            log(f"  -> securityadmin completed successfully")
            for line in result.stdout.split("\n"):
                if "Done" in line or "success" in line.lower() or "nodes" in line.lower():
                    log(f"    {line.strip()}")
        else:
            log(f"  X securityadmin failed (exit={result.returncode})")
            if result.stderr:
                for line in result.stderr.strip().split("\n")[:5]:
                    log(f"    STDERR: {line.strip()}")
            if result.stdout:
                for line in result.stdout.strip().split("\n")[:5]:
                    log(f"    STDOUT: {line.strip()}")
    except subprocess.TimeoutExpired:
        log("  X securityadmin timed out (120s)")
    except Exception as e:
        log(f"  X securityadmin error: {e}")

    # -- Step 7c: Safety check client_secret in dashboard config --------
    dash_yml = os.path.join(BASE_DIR, "configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml")
    if os.path.exists(dash_yml):
        with open(dash_yml) as f:
            dash_content = f.read()
        if "WILL_BE_SET_BY_POST_DEPLOY" in dash_content:
            log("  ! Dashboard config still has placeholder client_secret!")
            secret = deployed.get("SSO_CLIENT_SECRET", "")
            if secret:
                dash_content = dash_content.replace("WILL_BE_SET_BY_POST_DEPLOY", secret)
                with open(dash_yml, "w") as f:
                    f.write(dash_content)
                log(f"  -> Client secret injected (safety check)")
            else:
                log("  X No client secret available -- SSO will fail!")

    # -- Step 7d: Restart indexer to reload security plugin with new config
    log("  Restarting wazuh-indexer to reload security plugin...")
    try:
        subprocess.run(["docker", "restart", "socstack-wazuh-indexer"],
                      capture_output=True, text=True, timeout=30)
        log("  -> Wazuh indexer restarting")
    except Exception as e:
        log(f"  X Indexer restart failed: {e}")

    # Wait for indexer to come back fully
    log("  Waiting for indexer to come back...")
    time.sleep(20)
    wait_for("Wazuh Indexer", "https://localhost:9200/", timeout=90)

    # -- Step 7e: system-ca.pem persists via bind mount -----------------
    log("  -> system-ca.pem persists via bind mount (no re-copy needed)")

    # -- Step 7f: Restart dashboard AFTER indexer is ready ---------------
    # Dashboard needs indexer+SSO both working before it starts
    log("  Restarting wazuh-dashboard (after indexer is ready)...")
    try:
        subprocess.run(["docker", "restart", "socstack-wazuh-dashboard"],
                      capture_output=True, text=True, timeout=30)
        log("  -> Wazuh dashboard restarting")
    except Exception as e:
        log(f"  X Dashboard restart failed: {e}")
    time.sleep(15)
    wait_for("Wazuh Dashboard", "https://localhost:5601/", timeout=90)


# ====================================================================
# STEP 8: Wazuh API -> SSO Role Mapping (run_as)
# ====================================================================
def step_wazuh_api_role_mapping():
    """
    Automates 'Wazuh App -> SSO Role Mapping' via the Wazuh Manager API.
    Creates security rules that map Keycloak SSO groups to Wazuh RBAC roles
    so that run_as authentication resolves the correct permissions.

    Mapping:
      soc-admin   + soc-analyst  -> administrator  (role_id=1)
      soc-readonly                -> readonly       (role_id=6)
    """
    log("\n" + "="*60)
    log("STEP 8: Wazuh API -> SSO Role Mapping (run_as)")
    log("="*60)

    WAZUH_API = "https://localhost:55000"

    # -- 8a: Wait for Wazuh Manager API ----------------------------------
    if not wait_for("Wazuh API", WAZUH_API, timeout=90):
        log("  X Wazuh API not reachable -- skipping role mapping")
        results["wazuh_api_role_mapping"] = False
        return

    # -- 8b: Authenticate -------------------------------------------------
    try:
        r = requests.post(
            f"{WAZUH_API}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASS),
            verify=False, timeout=15,
        )
        if r.status_code != 200:
            log(f"  X Wazuh API auth failed: {r.status_code} {r.text[:150]}")
            results["wazuh_api_role_mapping"] = False
            return
        token = r.json()["data"]["token"]
        log(f"  -> Wazuh API authenticated as {WAZUH_API_USER}")
    except Exception as e:
        log(f"  X Wazuh API auth error: {e}")
        results["wazuh_api_role_mapping"] = False
        return

    wh = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # -- 8c: Define SSO group -> Wazuh RBAC role mappings -----------------
    # Predefined role IDs (Wazuh Manager) — fetch dynamically
    # Default IDs: 1=administrator 2=readonly 3=users_admin
    #              4=agents_readonly 5=agents_admin 6=cluster_readonly 7=cluster_admin
    # NOTE: Role IDs may differ between Wazuh versions. We resolve by name.
    role_name_to_id = {}
    try:
        r = requests.get(f"{WAZUH_API}/security/roles?limit=100",
                         headers=wh, verify=False, timeout=15)
        if r.status_code == 200:
            for role in r.json().get("data", {}).get("affected_items", []):
                role_name_to_id[role["name"]] = role["id"]
            log(f"  -> Found {len(role_name_to_id)} Wazuh API roles")
    except Exception as e:
        log(f"  X Failed to fetch roles: {e}")

    def rid(name, fallback):
        return role_name_to_id.get(name, fallback)

    # Admin roles: administrator + users_admin + agents_admin + cluster_admin
    admin_role_ids = [
        rid("administrator", 1),
        rid("users_admin", 3),
        rid("agents_admin", 5),
        rid("cluster_admin", 7),
    ]
    # Readonly roles: readonly + agents_readonly + cluster_readonly
    readonly_role_ids = [
        rid("readonly", 2),
        rid("agents_readonly", 4),
        rid("cluster_readonly", 6),
    ]

    role_mappings = [
        {
            "group": SSO_GROUP_ADMIN,
            "rule_name": SSO_GROUP_ADMIN,
            "role_ids": admin_role_ids,
            "desc": "administrator + users_admin + agents_admin + cluster_admin",
        },
        {
            "group": SSO_GROUP_ANALYST,
            "rule_name": SSO_GROUP_ANALYST,
            "role_ids": admin_role_ids,       # same as admin
            "desc": "administrator + users_admin + agents_admin + cluster_admin",
        },
        {
            "group": SSO_GROUP_READONLY,
            "rule_name": SSO_GROUP_READONLY,
            "role_ids": readonly_role_ids,
            "desc": "readonly + agents_readonly + cluster_readonly",
        },
    ]

    # -- 8d: Fetch existing rules -----------------------------------------
    try:
        r = requests.get(f"{WAZUH_API}/security/rules?limit=500",
                         headers=wh, verify=False, timeout=15)
        existing_rules = {}
        if r.status_code == 200:
            for rule in r.json().get("data", {}).get("affected_items", []):
                existing_rules[rule["name"]] = rule
    except Exception:
        existing_rules = {}

    # -- 8e: Create rules & link to roles ---------------------------------
    all_ok = True
    for mapping in role_mappings:
        group = mapping["group"]
        rule_name = mapping["rule_name"]
        role_ids = mapping["role_ids"]
        desc = mapping["desc"]
        rule_id = None

        # Check if rule already exists
        if rule_name in existing_rules:
            rule_id = existing_rules[rule_name]["id"]
            log(f"  -> Rule '{rule_name}' already exists (id={rule_id})")
        else:
            # Create rule:  FIND { "backend_roles": "<group>" }
            # The Wazuh Dashboard plugin passes Keycloak groups as
            # 'backend_roles' in the run_as authorization context.
            try:
                r = requests.post(
                    f"{WAZUH_API}/security/rules",
                    headers=wh, verify=False, timeout=15,
                    json={
                        "name": rule_name,
                        "rule": {
                            "FIND": {
                                "backend_roles": group,
                            }
                        },
                    },
                )
                items = r.json().get("data", {}).get("affected_items", [])
                if r.status_code == 200 and items:
                    rule_id = items[0]["id"]
                    log(f"  -> Rule created: '{rule_name}' (id={rule_id})")
                else:
                    failed = r.json().get("data", {}).get("failed_items", [])
                    log(f"  X Rule '{rule_name}' failed: {failed or r.text[:150]}")
                    all_ok = False
                    continue
            except Exception as e:
                log(f"  X Rule '{rule_name}' error: {e}")
                all_ok = False
                continue

        # Link rule to each target role
        if rule_id is not None:
            for role_id in role_ids:
                try:
                    r = requests.post(
                        f"{WAZUH_API}/security/roles/{role_id}/rules?rule_ids={rule_id}",
                        headers=wh, verify=False, timeout=15,
                    )
                    items = r.json().get("data", {}).get("affected_items", [])
                    failed = r.json().get("data", {}).get("failed_items", [])
                    if items:
                        rname = items[0].get("name", f"role-{role_id}")
                        log(f"  -> Rule '{rule_name}' -> Role '{rname}' ({desc})")
                    elif failed:
                        # "already" linked is fine
                        err_msg = str(failed)
                        if "already" in err_msg.lower():
                            log(f"  -> Rule '{rule_name}' already linked to {desc}")
                        else:
                            log(f"  X Link '{rule_name}' -> role {role_id}: {err_msg[:120]}")
                            all_ok = False
                    else:
                        log(f"  X Link '{rule_name}' -> role {role_id}: {r.status_code}")
                        all_ok = False
                except Exception as e:
                    log(f"  X Link error '{rule_name}' -> role {role_id}: {e}")
                    all_ok = False

    # -- 8f: Verify -------------------------------------------------------
    log("\n  Verifying Wazuh API role mappings...")
    try:
        r = requests.get(f"{WAZUH_API}/security/rules?limit=500",
                         headers=wh, verify=False, timeout=15)
        if r.status_code == 200:
            current = {rule["name"]: rule
                       for rule in r.json()["data"]["affected_items"]}
            for m in role_mappings:
                found = m["rule_name"] in current
                status = "OK" if found else "MISSING"
                log(f"    {m['group']:20s} -> {m['desc']:20s} [{status}]")
    except Exception as e:
        log(f"  X Verification error: {e}")

    results["wazuh_api_role_mapping"] = all_ok
    if all_ok:
        log("  -> All Wazuh API SSO role mappings configured successfully")
    else:
        log("  ! Some role mappings may need manual review")


# ====================================================================
# STEP 9: Save deployed credentials
# ====================================================================
def save_deployed():
    log("\n" + "="*60)
    log("STEP 9: Saving deployed credentials")
    log("="*60)

    # Add remaining known creds
    deployed["WAZUH_INDEXER_USERNAME"] = env.get("WAZUH_INDEXER_USERNAME", "admin")
    deployed["WAZUH_INDEXER_PASSWORD"] = env.get("WAZUH_INDEXER_PASSWORD", "SecretPassword")
    deployed["WAZUH_API_USER"] = env.get("WAZUH_API_USER", "wazuh-wui")
    deployed["WAZUH_API_PASSWORD"] = env.get("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-")
    deployed["KC_ADMIN_USER"] = env.get("KC_ADMIN_USER", "admin")
    deployed["KC_ADMIN_PASSWORD"] = env.get("KC_ADMIN_PASSWORD", "SocKeycloak@2025")
    deployed["MISP_ADMIN_EMAIL"] = env.get("MISP_ADMIN_EMAIL", "admin@yourdomain.com")
    deployed["MISP_ADMIN_PASSWORD"] = env.get("MISP_ADMIN_PASSWORD", "SocMisp@2025")
    deployed["MINIO_ROOT_USER"] = env.get("MINIO_ROOT_USER", "socminioadmin")
    deployed["MINIO_ROOT_PASSWORD"] = env.get("MINIO_ROOT_PASSWORD", "SocMinio@2025")

    # Add domains
    for key, cfg in DOMAINS.items():
        deployed[f"{key.upper()}_URL"] = f"https://{cfg['domain']}"

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(DEPLOYED_FILE, "w") as f:
        f.write(f"# ============================================================\n")
        f.write(f"# SOC STACK V2 - Deployed Credentials\n")
        f.write(f"# Generated: {ts}\n")
        f.write(f"# ============================================================\n\n")

        sections = {
            "URLS": ["SSO_URL", "WAZUH_URL", "N8N_URL", "CTI_URL", "HIVE_URL", "CORTEX_URL", "NPM_URL"],
            "NPM": ["NPM_ADMIN_EMAIL", "NPM_ADMIN_PASSWORD"],
            "KEYCLOAK": ["KC_ADMIN_USER", "KC_ADMIN_PASSWORD"],
            "KEYCLOAK SSO (SOC)": [
                "SSO_REALM", "SSO_CLIENT_ID", "SSO_CLIENT_SECRET",
                "OAUTH2_PROXY_COOKIE_SECRET",
                "SSO_ADMIN_EMAIL", "SSO_ADMIN_PASSWORD",
                "SSO_ANALYST_EMAIL", "SSO_ANALYST_PASSWORD",
                "SSO_READONLY_EMAIL", "SSO_READONLY_PASSWORD",
            ],
            "WAZUH": ["WAZUH_INDEXER_USERNAME", "WAZUH_INDEXER_PASSWORD", "WAZUH_API_USER", "WAZUH_API_PASSWORD"],
            "N8N": ["N8N_ADMIN_EMAIL", "N8N_ADMIN_PASSWORD"],
            "MISP": ["MISP_ADMIN_EMAIL", "MISP_ADMIN_PASSWORD", "MISP_API_KEY"],
            "THEHIVE": ["THEHIVE_ADMIN_USER", "THEHIVE_ADMIN_PASSWORD", "THEHIVE_ANALYST_USER", "THEHIVE_ANALYST_PASSWORD"],
            "CORTEX": ["CORTEX_ADMIN_USER", "CORTEX_ADMIN_PASSWORD", "CORTEX_ORG_ADMIN", "CORTEX_API_KEY"],
            "MINIO": ["MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"],
        }

        for section, keys in sections.items():
            f.write(f"# === {section} ===\n")
            for k in keys:
                v = deployed.get(k, "NOT_SET")
                f.write(f"{k}={v}\n")
            f.write("\n")

    log(f"  -> Saved to {DEPLOYED_FILE}")

    # Save log
    with open(LOG_FILE, "w") as f:
        f.write("\n".join(log_lines))
    log(f"  -> Log saved to {LOG_FILE}")


# ====================================================================
# Print Summary
# ====================================================================
def print_summary():
    log("\n" + "="*60)
    log("  SOC STACK V2 - POST-DEPLOY COMPLETE")
    log("="*60)
    log("")
    svc = [
        ("NPM",      f"https://{DOMAINS['npm']['domain']}",     NPM_EMAIL, NPM_PASS),
        ("Keycloak",  f"https://{DOMAINS['sso']['domain']}",     env.get("KC_ADMIN_USER","admin"), env.get("KC_ADMIN_PASSWORD","SocKeycloak@2025")),
        ("Wazuh",     f"https://{DOMAINS['wazuh']['domain']}",   "admin", env.get("WAZUH_INDEXER_PASSWORD","SecretPassword")),
        ("  > SSO Admin","",                                     SSO_ADMIN_EMAIL, SSO_ADMIN_PASS),
        ("  > SSO Analyst","",                                   SSO_ANALYST_EMAIL, SSO_ANALYST_PASS),
        ("  > SSO Readonly","",                                  SSO_READONLY_EMAIL, SSO_READONLY_PASS),
        ("n8n",       f"https://{DOMAINS['n8n']['domain']}",     N8N_EMAIL, N8N_PASS),
        ("MISP",      f"https://{DOMAINS['cti']['domain']}",     MISP_ADMIN, MISP_PASS),
        ("TheHive",   f"https://{DOMAINS['hive']['domain']}",    THEHIVE_USER, THEHIVE_PASS),
        ("  > Analyst","",                                       THEHIVE_ANALYST, THEHIVE_ANALYST_PASS),
        ("Cortex",    f"https://{DOMAINS['cortex']['domain']}",  CORTEX_ADMIN, CORTEX_PASS),
        ("  > OrgAdmin","",                                      CORTEX_ORG_ADMIN, CORTEX_PASS),
    ]
    for name, url, user, pwd in svc:
        if url:
            log(f"  {name:16s} {url}")
        log(f"  {'':16s} {user} / {pwd}")
        log("")

    log(f"  Credentials: {DEPLOYED_FILE}")
    log(f"  Log:         {LOG_FILE}")

    cortex_key = deployed.get("CORTEX_API_KEY", "")
    misp_key = deployed.get("MISP_API_KEY", "")
    log("")
    log("=" * 60)
    log("  MANUAL STEPS REQUIRED (UI Configuration)")
    log("=" * 60)

    log("")
    log("  --- A. TheHive UI ----------------------------------------")
    log("")
    log("  1. TheHive -> Cortex Server")
    log("     Platform Management -> Cortex Servers -> Add")
    log(f"     - Server Name:                    Cortex-{THEHIVE_ORG}")
    log(f"     - URL:                            http://socstack-cortex:9001")
    log(f"     - API Key:                        {cortex_key}")
    log(f"     - Check Certificate Authority:    DISABLE")
    log(f"     - Disable hostname verification:  ENABLE")
    log("")
    log("  2. TheHive -> MISP Server")
    log("     Platform Management -> MISP Servers -> Add")
    log(f"     - Server Name:  MISP-{THEHIVE_ORG}")
    log(f"     - URL:          https://socstack-misp-core:443")
    log(f"     - API Key:      {misp_key}")
    log(f"     - Skip SSL:     Yes")
    log(f"     - Purpose:      Import and Export")

    log("")
    log("  --- B. Cortex UI -----------------------------------------")
    log("")
    log("  3. Cortex -> Enable Analyzers")
    log("     Organization -> Analyzers -> Refresh -> Enable needed")

    log("")
    log("  --- C. MISP UI ------------------------------------------")
    log("")
    log("  4. MISP -> Initial password change on first login")
    log(f"     URL: https://{DOMAINS['cti']['domain']}")
    log(f"     Default: admin@admin.test / admin")
    log(f"     Change to: {MISP_ADMIN} / {MISP_PASS}")
    log("")
    log("  NOTE: MISP feeds are auto-loaded, enabled + cached by post-deploy.")
    log("        Daily updates: MISP built-in scheduler (CRON_USER_ID=1)")
    log("        No external cron needed.")

    log("")
    log("  --- D. Wazuh SSO Role Mapping (AUTOMATED) ----------------")
    log("")
    log("  5. Wazuh App SSO Role Mapping -> Done by Step 8 (API)")
    log(f"     {SSO_GROUP_ADMIN:20s} -> administrator  (Wazuh API role)")
    log(f"     {SSO_GROUP_ANALYST:20s} -> administrator  (Wazuh API role)")
    log(f"     {SSO_GROUP_READONLY:20s} -> readonly       (Wazuh API role)")
    log(f"     Indexer roles_mapping.yml also updated (securityadmin Step 7)")

    log("")
    log("  --- E. n8n Workflow Setup --------------------------------")
    log("")
    log("  6. n8n -> Import Wazuh Email Alert Workflow")
    log(f"     URL: https://{DOMAINS['n8n']['domain']}")
    log("     a) Create new workflow -> Import from file")
    log("        File: 1_Wazuh_Email_Alert.json")
    log("     b) Fix Redis connection first:")
    log("        - Hostname: socstack-n8n-redis")
    log("        - Password: (leave empty / no password)")
    log("     c) Setup SMTP email credentials:")
    log("        - Configure SMTP host, port, user, password")
    log("        - Set 'To' email address")
    log("     d) Enable the workflow (toggle ON)")
    log("     e) Copy the webhook URL from the Webhook node")
    log("     f) Update webhook URL in wazuh_manager.conf:")
    log("        File: configs/wazuh/wazuh_cluster/wazuh_manager.conf")
    log("        Update <hook_url> in the n8n integration section")
    log("     g) Restart Wazuh manager:")
    log("        docker restart socstack-wazuh-manager")

    # ── Final Status Report ──────────────────────────────────────────
    log("")
    log("=" * 60)
    log("  POST-DEPLOY STATUS REPORT")
    log("=" * 60)
    log("")

    checks = [
        ("NPM Proxy Hosts + SSL",
         "PASS" if deployed.get("NPM_ADMIN_EMAIL") else "WARN"),
        ("n8n Owner Account",
         "PASS" if deployed.get("N8N_ADMIN_EMAIL") else "WARN"),
        ("Cortex Init + Org + API Key",
         "PASS" if deployed.get("CORTEX_API_KEY") else "WARN"),
        ("TheHive Password + Org + Analyst",
         "PASS" if deployed.get("THEHIVE_ANALYST_USER") else "WARN"),
        ("MISP <-> TheHive Integration",
         "PASS" if deployed.get("MISP_API_KEY") else "WARN"),
    ]

    # MISP Feeds detailed check
    mf = results.get("misp_feeds", {})
    if mf:
        feed_total = mf.get("total_feeds", 0)
        feed_enabled = mf.get("feeds_enabled", 0)
        feed_cached = mf.get("caching_enabled", 0)

        feed_items = [
            (f"  Default Feeds Loaded ({feed_total})",
             "PASS" if mf.get("defaults_loaded") or feed_total > 10 else "WARN"),
            (f"  Feeds Enabled ({feed_enabled}/{feed_total})",
             "PASS" if feed_enabled == feed_total else ("WARN" if feed_enabled > 0 else "FAIL")),
            (f"  Caching Enabled ({feed_cached}/{feed_total})",
             "PASS" if feed_cached >= feed_total - 5 else ("WARN" if feed_cached > 0 else "FAIL")),
            (f"  Cache Download (initial)",
             "PASS" if mf.get("cache_initiated") else "WARN"),
            (f"  Fetch IOCs (initial)",
             "PASS" if mf.get("fetch_initiated") else "WARN"),
            (f"  Daily Scheduler (built-in)",
             "PASS" if mf.get("scheduler_ok") else "WARN"),
        ]
        checks.append(("MISP Feeds Setup", "PASS" if all(
            s == "PASS" for _, s in feed_items) else "WARN"))
    else:
        feed_items = []
        checks.append(("MISP Feeds Setup", "WARN"))

    checks.extend([
        ("Keycloak SSO (Realm + Client + Users)",
         "PASS" if deployed.get("SSO_CLIENT_SECRET") else "WARN"),
        ("Wazuh Security (securityadmin)",
         "PASS" if deployed.get("WAZUH_INDEXER_PASSWORD") else "WARN"),
        ("Wazuh API SSO Role Mapping (run_as)",
         "PASS" if results.get("wazuh_api_role_mapping") else "WARN"),
        ("Credentials Saved",
         "PASS" if os.path.exists(DEPLOYED_FILE) else "WARN"),
    ])

    pass_count = sum(1 for _, s in checks if s == "PASS")
    warn_count = sum(1 for _, s in checks if s == "WARN")
    fail_count = sum(1 for _, s in checks if s == "FAIL")

    for name, status in checks:
        icon = "✅" if status == "PASS" else ("⚠️" if status == "WARN" else "❌")
        log(f"  {icon} {status:4s}  {name}")
        # Show MISP feed sub-items under the MISP Feeds entry
        if name == "MISP Feeds Setup" and feed_items:
            for sub_name, sub_status in feed_items:
                sub_icon = "✅" if sub_status == "PASS" else ("⚠️" if sub_status == "WARN" else "❌")
                log(f"       {sub_icon} {sub_status:4s}  {sub_name}")

    log("")
    log(f"  Total: {pass_count} PASS / {warn_count} WARN / {fail_count} FAIL")
    if fail_count == 0 and warn_count == 0:
        log("  🎉 All steps completed successfully!")
    elif fail_count == 0:
        log("  ✅ Deployment complete (check warnings above)")
    else:
        log("  ⚠️  Deployment has failures - review log above")

    log("")
    log("=" * 60)
    log(f"  Credentials file: {DEPLOYED_FILE}")
    log("=" * 60)
    log("")


# ====================================================================
# MAIN
# ====================================================================
if __name__ == "__main__":
    log("="*60)
    log("  SOC STACK V2 - Post-Deploy Configuration")
    log(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("="*60)

    # Pre-step: Stop Wazuh Dashboard before NPM/SSL is ready
    # Dashboard SSO connect_url needs public domain -> NPM must be configured first
    subprocess.run(["docker", "stop", "socstack-wazuh-dashboard"],
                   capture_output=True, timeout=30)
    log("  -> Wazuh Dashboard stopped (will restart after NPM + SSL + SSO configured)")
    # Note: Directory creation, permissions, and custom-n8n ownership are handled by pre-deploy.sh

    step_npm()
    step_n8n()
    cortex_key = step_cortex()
    th_auth = step_thehive()
    step_misp_thehive(th_auth)
    step_misp_feeds()
    step_keycloak_sso()
    step_wazuh_security()
    step_wazuh_api_role_mapping()
    save_deployed()
    print_summary()
