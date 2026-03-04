# SOC Stack — Unified Security Operations Center

A production-ready, fully automated Docker-based SOC (Security Operations Center) stack deploying **17 containers** on a single server with **Keycloak SSO**, **automated SSL**, and **end-to-end integration** between all services.

```
  Wazuh Alert → custom-n8n webhook → n8n workflow → Email + TheHive Alert
                                                        ↓
                                              Incident Response Team
                                              (Cases, Cortex Analysis, MISP Intel)
```

---

## Table of Contents

- [Architecture](#architecture)
- [Services (17 Containers)](#services-17-containers)
- [Server Requirements](#server-requirements)
- [Quick Start (6 Steps)](#quick-start-6-steps)
- [Pre-Deployment (Automated)](#step-3-pre-deployment-checks)
- [Post-Deployment (Automated)](#step-6-post-deployment-configuration)
- [Post-Deployment UI Configuration (Manual)](#post-deployment-ui-configuration-manual)
- [Credentials & API Keys](#credentials--api-keys)
- [Wazuh SSO (Keycloak OpenID Connect)](#wazuh-sso-keycloak-openid-connect)
- [n8n Wazuh Integration (Email + TheHive)](#n8n-wazuh-integration-email--thehive)
- [Directory Structure](#directory-structure)
- [Management Commands](#management-commands)
- [Troubleshooting](#troubleshooting)
- [Known Issues & Fixes](#known-issues--fixes)
- [Re-Deployment / Updates](#re-deployment--updates)
- [Files Reference](#files-reference)

---

## Architecture

```
                        Internet
                           │
                   ┌───────┴────────┐
                   │  Nginx Proxy   │  ← SSL termination (Let's Encrypt)
                   │    Manager     │  ← Reverse proxy for all 7 services
                   └───────┬────────┘
       ┌──────┬──────┬─────┼──────┬──────┬──────┐
       ▼      ▼      ▼     ▼      ▼      ▼      ▼
    Wazuh  Keycloak  n8n  MISP  TheHive Cortex  NPM
    SIEM    SSO    Workflow CTI  Cases  Analysis Admin
      │       ▲                    │       │
      │       │  OpenID Connect    │       │
      └───────┘    (SSO)           └───┬───┘
      │                            Cortex API
      │  custom-n8n webhook            │
      └──────────► n8n ───────► TheHive Alert
                    │               │
                    ├──► Email      │
                    │           Cortex ──► MISP
                    │           (on-demand IOC
                    │            analyzer lookup)
```

### Integration Flow

| From | To | Method | Purpose |
|------|----|--------|---------|
| Wazuh Manager | n8n | custom-n8n webhook integration | Forward security alerts |
| n8n | Email (SMTP) | SMTP credentials | Email notifications |
| n8n | TheHive | TheHive API (analyst account) | Create alerts for incident response |
| TheHive | Cortex | Cortex API key | Observable analysis (VirusTotal, etc.) |
| Cortex | MISP | MISP API key (via Cortex MISP analyzer) | On-demand threat intelligence lookups for observables |
| Wazuh Dashboard | Keycloak | OpenID Connect (OIDC) | Single Sign-On authentication |

---

## Services (17 Containers)

| # | Container | Image | Ports | Purpose |
|---|-----------|-------|-------|---------|
| 1 | `socstack-nginx` | jc21/nginx-proxy-manager | 80, 443, 60081 | Reverse proxy + Let's Encrypt SSL |
| 2 | `socstack-keycloak` | quay.io/keycloak/keycloak | 8081 | SSO (OpenID Connect) |
| 3 | `socstack-keycloak-db` | postgres:15-alpine | — | Keycloak database |
| 4 | `socstack-wazuh-manager` | wazuh/wazuh-manager:${WAZUH_VERSION} | 1514, 1515, 514/udp, 55000 | SIEM manager + agent listener |
| 5 | `socstack-wazuh-indexer` | wazuh/wazuh-indexer:${WAZUH_VERSION} | 9200 | OpenSearch indexer |
| 6 | `socstack-wazuh-dashboard` | wazuh/wazuh-dashboard:${WAZUH_VERSION} | 5601 | Wazuh Dashboard UI (SSO enabled) |
| 7 | `socstack-thehive` | strangebee/thehive:5.2 | 9000 | Case management |
| 8 | `socstack-cortex` | thehiveproject/cortex:3.1.8-1 | 9001 | Observable analysis engine |
| 9 | `socstack-cassandra` | cassandra:4.1 | — | TheHive primary database |
| 10 | `socstack-elasticsearch` | elasticsearch:7.17.15 | — | Cortex + TheHive search index |
| 11 | `socstack-minio` | minio/minio | 9002, 9003 | TheHive S3 file storage |
| 12 | `socstack-misp-core` | misp/misp-core | 8443 | Threat intelligence platform |
| 13 | `socstack-misp-db` | mariadb:10.11 | — | MISP database |
| 14 | `socstack-misp-redis` | valkey:7.2 | — | MISP cache |
| 15 | `socstack-misp-modules` | misp/misp-modules | — | MISP enrichment modules |
| 16 | `socstack-n8n` | n8nio/n8n | 5678 | Workflow automation |
| 17 | `socstack-n8n-redis` | redis:7-alpine | — | n8n job queue |

All containers run on a single `socstack_net` Docker bridge network.

---

## Server Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **OS** | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| **RAM** | 16 GB | 32 GB |
| **Disk** | 50 GB free | 100 GB+ SSD |
| **Docker** | 24+ with Compose v2 | Latest stable |
| **Ports** | 80, 443 open to internet | Firewall restricted |
| **Kernel** | `vm.max_map_count=262144` | Auto-set by pre-deploy.sh |
| **DNS** | 7 A records → server IP | All pointing to same server |

### Required DNS A Records

Create these **before deployment** — all pointing to your server's public IP:

| Domain | Service |
|--------|---------|
| `sso.yourdomain.com` | Keycloak SSO |
| `wazuh.yourdomain.com` | Wazuh Dashboard |
| `n8n.yourdomain.com` | n8n Workflows |
| `cti.yourdomain.com` | MISP CTI |
| `hive.yourdomain.com` | TheHive Cases |
| `cortex.yourdomain.com` | Cortex Analysis |
| `npm.yourdomain.com` | Nginx Proxy Manager |

---

## Quick Start (6 Steps)

### Step 1: Configure Environment

```bash
# On your LOCAL machine (where deploy files are)
cp .env.example .env
nano .env     # Fill in ALL required fields
```

**Required changes in `.env`:**
- `SERVER_IP` — your server's public IP address
- All `*_DOMAIN` fields — your actual domain names
- All `*_PASSWORD` fields — change every `ChangeMe_*` to strong passwords
- All `*_EMAIL` fields — your actual email addresses
- `MISP_ORG` / `THEHIVE_ORG_NAME` / `CORTEX_ORG_NAME` — your organization name

> **Credential strategy:** User-facing and frequently-changed passwords are in `.env`. Internal backend passwords (Keycloak DB, MinIO, MISP DB, MISP Redis) are hardcoded in `docker-compose.yml` since they never change after deployment.

### Step 2: Copy Files to Server

```bash
# SCP the entire deploy directory to the server
scp -P YOUR_SSH_PORT -r deploy/* root@YOUR_SERVER_IP:/opt/socstack/
```

### Step 3: Pre-Deployment Checks

```bash
# SSH into the server
ssh -p YOUR_SSH_PORT root@YOUR_SERVER_IP

# Run pre-deploy (self-fixes CRLF if SCP'd from Windows)
chmod +x /opt/socstack/pre-deploy.sh
sudo /opt/socstack/pre-deploy.sh
```

**pre-deploy.sh automatically handles (30 checks):**

| Section | What It Does |
|---------|--------------|
| 1. System | Validates OS, RAM (16GB+), disk (50GB+), root access |
| 2. Docker | Verifies Docker + Compose installed, daemon running |
| 3. Kernel | Sets `vm.max_map_count=262144` (persistent) |
| 4. Ports | Checks all required ports available |
| 5. DNS | Verifies all 7 domain A records resolve to `SERVER_IP` |
| 6. Directories | Creates 24 data dirs + 8 config dirs under `/opt/socstack/` |
| 6b. CRLF Fix | Converts Windows `\r\n` → Unix `\n` on ALL configs/scripts (critical for files SCP'd from Windows) |
| 7. Permissions | Fixes ownership: Keycloak (uid 1000), TheHive (uid 1000), n8n (uid 1000), custom-n8n (mode 750) |
| 8. Wazuh Certs | Auto-generates Wazuh TLS certificates using `wazuh-certs-generator:0.0.2` (if missing), sets permissions to 444 |

Expected result: **30 PASS, 0 FAIL**

### Step 4: Start the Stack

```bash
cd /opt/socstack
docker compose up -d
```

Wait **3-5 minutes** for all 17 containers to initialize:
```bash
# Watch container startup
docker compose ps

# Check for unhealthy containers
docker ps --filter "health=unhealthy"

# Tail specific service logs
docker compose logs -f socstack-keycloak
```

> **Note:** Cassandra and Elasticsearch take longest (1-2 min). TheHive and Cortex depend on them.

### Step 5: Post-Deployment Configuration

```bash
python3 /opt/socstack/post-deploy.py
```

This takes **2-5 minutes** and automatically configures all services. See [Post-Deployment details](#step-6-post-deployment-configuration).

### Step 6: Run Tests

```bash
python3 /opt/socstack/test-stack.py
```

Expected: **59/60 PASS, 0 FAIL, 1 WARN** (98%+)

Then follow the [Post-Deployment UI Guide](#post-deployment-ui-configuration-manual) for remaining manual steps.

---

## Step 6: Post-Deployment Configuration

`post-deploy.py` automatically configures all services after `docker compose up -d`:

| Step | Service | Action | Details |
|------|---------|--------|---------|
| Pre | Keycloak | Fix permissions | `chown -R 1000:0` data dir for gzip theme cache |
| Pre | Wazuh Manager | Fix custom-n8n | `chmod`/`chown` integration scripts inside container to match `/var/ossec/integrations/slack` |
| 1 | **NPM** | Proxy hosts + SSL | Creates 7 reverse proxy hosts, requests Let's Encrypt SSL certs (skips existing) |
| 2 | **n8n** | Owner account | Creates admin owner (disables public signup permanently) |
| 3 | **Cortex** | Full setup | Migrates DB, creates superadmin, org, org admin, generates API key |
| 4 | **TheHive** | Full setup | Changes default password, creates org `CODESEC`, creates analyst user |
| 5 | **MISP** | API key | Retrieves API key from MISP database, verifies it works |
| 6 | **Keycloak SSO** | Full SSO setup | Creates realm `wazuh`, OIDC client, groups, SSO users, injects client secret into Wazuh Dashboard config |
| 7 | **Wazuh Security** | Apply configs | Copies system CA bundle into indexer (for Let's Encrypt verification), runs `securityadmin.sh`, verifies client_secret not placeholder, restarts indexer + dashboard |
| 8 | **Wazuh API** | SSO role mapping | Creates security rules via Wazuh Manager API (port 55000) to map SSO groups to Wazuh App RBAC roles (run_as) |
| 9 | **Save** | Credentials | Writes all credentials + API keys to `.env.deployed` |

**Safety features:**
- Idempotent — safe to re-run multiple times
- SSL skip logic — avoids Let's Encrypt rate limits on re-deploys
- SSO client_secret safety check — 3 layers of protection against placeholder values
- All steps have error handling with clear messages

---

## Post-Deployment UI Configuration (Manual)

After `post-deploy.py` completes, some UI configurations must be done manually.

> **Full step-by-step guide with screenshots:** See [`POST-DEPLOY-UI-GUIDE.md`](POST-DEPLOY-UI-GUIDE.md) (shareable standalone document)

| Section | Task | Time |
|---------|------|------|
| **A** | TheHive → Cortex server integration | 2 min |
| **B** | Cortex → Enable MISP analyzer (primary, free) + other analyzers | 5 min |
| **C** | MISP → Enable, fetch & cache all threat feeds | 3 min |
| **D** | Wazuh Dashboard → SSO role mapping (**AUTOMATED** by Step 8) | 0 min |
| **E** | n8n → Import workflow, configure Redis/SMTP/TheHive, connect Wazuh webhook | 10 min |

All credentials needed are in `/opt/socstack/.env.deployed` on the server.

---

## Credentials & API Keys

After running `post-deploy.py`, all credentials are saved to `/opt/socstack/.env.deployed`.

### Service Logins

| Service | URL | Username | Password Key |
|---------|-----|----------|--------------|
| **NPM** | `https://<NPM_DOMAIN>` | `<NPM_ADMIN_EMAIL>` | `NPM_ADMIN_PASSWORD` |
| **Keycloak** | `https://<SSO_DOMAIN>` | `admin` | `KC_ADMIN_PASSWORD` |
| **Wazuh** (local) | `https://<WAZUH_DOMAIN>` | `admin` | `WAZUH_INDEXER_PASSWORD` |
| **Wazuh** (SSO admin) | `https://<WAZUH_DOMAIN>` | `<SSO_ADMIN_EMAIL>` | `SSO_ADMIN_PASSWORD` |
| **Wazuh** (SSO user) | `https://<WAZUH_DOMAIN>` | `<SSO_USER_EMAIL>` | `SSO_USER_PASSWORD` |
| **n8n** | `https://<N8N_DOMAIN>` | `<N8N_ADMIN_EMAIL>` | `N8N_ADMIN_PASSWORD` |
| **MISP** | `https://<MISP_DOMAIN>` | `<MISP_ADMIN_EMAIL>` | `MISP_ADMIN_PASSWORD` |
| **TheHive** (admin) | `https://<THEHIVE_DOMAIN>` | `admin@thehive.local` | `THEHIVE_ADMIN_PASSWORD` |
| **TheHive** (analyst) | `https://<THEHIVE_DOMAIN>` | `<THEHIVE_ANALYST_USER>` | `THEHIVE_ANALYST_PASSWORD` |
| **Cortex** (superadmin) | `https://<CORTEX_DOMAIN>` | `<CORTEX_ADMIN_USER>` | `CORTEX_ADMIN_PASSWORD` |
| **Cortex** (org admin) | `https://<CORTEX_DOMAIN>` | `<CORTEX_ORG_ADMIN>` | `CORTEX_ADMIN_PASSWORD` |
| **MinIO** | `http://<SERVER_IP>:9003` | `socminioadmin` | `SocMinio@2025` (hardcoded) |

### Auto-Generated API Keys

| Key | Location | Generated By | Used For |
|-----|----------|-------------|----------|
| `MISP_API_KEY` | `.env.deployed` | post-deploy.py (from MISP DB) | Cortex MISP analyzer + TheHive (optional) |
| `CORTEX_API_KEY` | `.env.deployed` + `.cortex-api-key` | post-deploy.py | TheHive → Cortex integration |
| `KC_WAZUH_CLIENT_SECRET` | `.env.deployed` | post-deploy.py | Wazuh Dashboard SSO |
| TheHive Analyst API Key | Generated manually in TheHive UI | Admin creates for analyst user | n8n → TheHive alert creation |

---

## Wazuh SSO (Keycloak OpenID Connect)

SSO is **fully automated** by `post-deploy.py`. No manual SSO configuration needed.

### How It Works

```
  Browser → Wazuh Dashboard → Keycloak (realm: wazuh)
                ↕                    ↕
         Wazuh Indexer ←── OpenID Connect (groups claim)
                                     ↓
                              Groups → Roles mapping:
                              soc-admin    → full admin (all_access)
                              soc-analyst  → full access (all_access)
                              soc-readonly → read-only (wazuh-* indices)
```

### SSO Users (Created by post-deploy.py)

| User | Keycloak Group | Backend Role | Access Level |
|------|---------------|-------------|-------------|
| `<SSO_ADMIN_EMAIL>` | `soc-admin` | `all_access` | Full admin |
| `<SSO_ANALYST_EMAIL>` | `soc-analyst` | `all_access` | Full access |
| `<SSO_USER_EMAIL>` | `soc-readonly` | `wazuh_user` + `kibana_user` | Read-only |

### SSO Login Flow

1. Go to `https://<WAZUH_DOMAIN>`
2. Click **"Log in with single sign-on"**
3. Redirected to Keycloak → login with SSO credentials
4. Redirected back to Wazuh Dashboard with correct role permissions

### Adding More SSO Users (Post-Deploy)

1. Login to Keycloak Admin → `https://<SSO_DOMAIN>`
2. Switch to realm **`wazuh`**
3. **Users** → **Add user** → set username, email, name
4. **Credentials** → set password (temporary: off)
5. **Groups** → join `soc-admin`, `soc-analyst`, or `soc-readonly`

### SSO Technical Details

The SSO chain involves 4 config files:

| File | Purpose |
|------|---------|
| `configs/wazuh/wazuh_indexer/config.yml` | OpenID auth domain: validates JWT tokens from Keycloak using `subject_key: preferred_username`, `roles_key: groups`. Needs system CA bundle for Let's Encrypt verification. |
| `configs/wazuh/wazuh_indexer/roles.yml` | Defines custom roles for cluster + indices access levels |
| `configs/wazuh/wazuh_indexer/roles_mapping.yml` | Maps Keycloak groups → OpenSearch roles: `soc-admin` → `all_access`, `soc-analyst` → `all_access`, `soc-readonly` → `wazuh_user` + `kibana_user` |
| `configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml` | Enables OpenID auth alongside basic auth, configures OIDC endpoints, client ID/secret, logout URL |

**Critical:** The indexer needs the system CA bundle at `/usr/share/wazuh-indexer/certs/system-ca.pem` to verify Keycloak's Let's Encrypt HTTPS certificate. This is automatically handled by `post-deploy.py` step 7.

---

## n8n Wazuh Integration (Email + TheHive)

Wazuh alerts are forwarded to n8n via a custom webhook integration, which then sends email notifications and creates TheHive alerts for the incident response team.

### How It Works

```
Wazuh Manager ──[custom-n8n integration]──► n8n Webhook
                                              │
                                    ┌─────────┴─────────┐
                                    ▼                     ▼
                              Send Email           Create TheHive Alert
                            (via SMTP)           (via TheHive API)
                                                        │
                                                        ▼
                                              IR Team → Cases → Cortex Analysis
```

### Custom Integration Files

| File | Purpose | Container Path |
|------|---------|----------------|
| `configs/wazuh/wazuh_cluster/custom-n8n` | Shell wrapper (calls Python script) | `/var/ossec/integrations/custom-n8n` |
| `configs/wazuh/wazuh_cluster/custom-n8n.py` | Python script (formats alert → HTTP POST) | `/var/ossec/integrations/custom-n8n.py` |
| `configs/n8n/1_Wazuh_Email_Alert.json` | n8n workflow definition (import into n8n) | `/opt/socstack/configs/n8n/` |

### Important Notes

- Integration scripts must have **Unix LF line endings** (not Windows CRLF) — `#!/bin/sh\r` is an invalid interpreter and causes "Couldn't execute command" errors
- `pre-deploy.sh` section 6b automatically converts CRLF → LF for all config/script files
- File permissions must be `750` with `root:wazuh` ownership (matching built-in integrations like `slack`)
- The webhook URL in `wazuh_manager.conf` must be the **Production URL** from n8n (not the test URL)

---

## Directory Structure

```
/opt/socstack/
├── docker-compose.yml              # Main compose file (17 services)
├── .env                            # Configuration (edit before deploy)
├── .env.example                    # Template with all variables
├── .env.deployed                   # Auto-generated credentials (after post-deploy)
├── .gitattributes                  # Forces LF line endings in Git
├── .cortex-api-key                 # Cortex API key (after post-deploy)
├── pre-deploy.sh                   # Pre-deployment checks & setup (30 checks)
├── post-deploy.py                  # Auto-configures everything after compose up
├── test-stack.py                   # Full test suite (59+ tests)
├── test-creds.py                   # Credential validation tests (30+ checks)
├── ssl-setup.py                    # SSL certificate helper
├── cortex-setup.py                 # Cortex initialization helper
├── README.md                       # This file
├── POST-DEPLOY-UI-GUIDE.md         # Shareable manual UI config guide (sections A-E)
│
├── configs/
│   ├── wazuh/
│   │   ├── certs.yml                       # Cert generator hostname config
│   │   ├── wazuh_indexer_ssl_certs/        # Generated TLS certificates (10 files)
│   │   ├── wazuh_indexer/
│   │   │   ├── wazuh.indexer.yml           # OpenSearch node config
│   │   │   ├── internal_users.yml          # Password hashes
│   │   │   ├── config.yml                  # Security config (OpenID auth domain)
│   │   │   ├── roles.yml                   # Role definitions
│   │   │   └── roles_mapping.yml           # Keycloak groups → OpenSearch roles
│   │   ├── wazuh_dashboard/
│   │   │   ├── opensearch_dashboards.yml   # Dashboard config (OIDC enabled)
│   │   │   └── wazuh.yml                   # Wazuh API connection config
│   │   └── wazuh_cluster/
│   │       ├── wazuh_manager.conf          # Manager configuration
│   │       ├── custom-n8n                  # Shell wrapper (webhook integration)
│   │       └── custom-n8n.py               # Python script (alert formatting)
│   ├── thehive/
│   │   └── cortex-application.conf         # Cortex config (elasticsearch: socstack-elasticsearch)
│   └── n8n/
│       └── 1_Wazuh_Email_Alert.json        # n8n workflow (import into n8n UI)
│
└── data/                                   # All persistent data volumes
    ├── nginx/                              # NPM data + Let's Encrypt certs
    │   ├── data/
    │   └── letsencrypt/
    ├── keycloak_postgres/                  # Keycloak PostgreSQL
    ├── keycloak_data/                      # Keycloak realm + gzip theme cache
    ├── n8n/                                # n8n workflows + SQLite DB
    ├── n8n_redis/                          # n8n job queue data
    ├── misp/                               # MISP data
    │   ├── configs/ logs/ files/ ssl/ gnupg/ mysql_data/
    ├── thehive/                            # TheHive + Cortex ecosystem
    │   ├── cassandra_data/ cassandra_logs/
    │   ├── elasticsearch_data/ elasticsearch_logs/
    │   ├── minio_data/
    │   ├── thehive_data/ thehive_files/ thehive_index/ thehive_logs/
    │   └── cortex_logs/
```

---

## Management Commands

```bash
cd /opt/socstack

# ── Start / Stop / Restart ──────────────────────────
docker compose up -d                          # Start all 17 containers
docker compose down                           # Stop all (preserves data)
docker compose restart                        # Restart all
docker restart socstack-<name>                # Restart single service

# ── Status & Health ─────────────────────────────────
docker compose ps                             # All container status
docker ps --filter "health=unhealthy"         # Find unhealthy containers
docker ps --filter "name=socstack-" --format "table {{.Names}}\t{{.Status}}"

# ── Logs ────────────────────────────────────────────
docker compose logs -f socstack-keycloak      # Tail specific service
docker compose logs --tail 100                # Last 100 lines all services
docker logs socstack-wazuh-manager --tail 50  # Single container logs

# ── Re-run Configuration (idempotent) ───────────────
python3 /opt/socstack/post-deploy.py          # Re-run post-deploy
python3 /opt/socstack/test-stack.py           # Run full test suite
python3 /opt/socstack/test-creds.py           # Run credential tests

# ── Wazuh Agent Management ─────────────────────────
docker exec socstack-wazuh-manager /var/ossec/bin/manage_agents -l   # List agents
docker exec socstack-wazuh-manager /var/ossec/bin/wazuh-control status  # Manager status

# ── Wazuh Integration Check ────────────────────────
docker exec socstack-wazuh-manager cat /var/ossec/logs/integrations.log  # Integration logs
docker exec socstack-wazuh-manager ls -la /var/ossec/integrations/       # Check permissions
```

---

## Troubleshooting

### Keycloak GUI broken (CSS returns application/json)

**Cause:** Keycloak (uid 1000) can't create `tmp/` subdirectory in the data volume. Gzip theme cache fails → HTTP 500 with wrong MIME types.

```bash
chown -R 1000:0 /opt/socstack/data/keycloak_data/
mkdir -p /opt/socstack/data/keycloak_data/tmp
docker restart socstack-keycloak
```

### Wazuh SSO returns 401 "Authentication Exception"

**Cause:** OpenID auth domain can't verify Keycloak's HTTPS cert (Let's Encrypt). Java sandbox blocks `/etc/ssl/certs/`.

```bash
# Copy system CA bundle into indexer
docker exec -u root socstack-wazuh-indexer \
  cp /etc/ssl/certs/ca-certificates.crt /usr/share/wazuh-indexer/certs/system-ca.pem

# Re-apply security configs
docker exec socstack-wazuh-indexer bash -c \
  "JAVA_HOME=/usr/share/wazuh-indexer/jdk \
   /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
   -cd /usr/share/wazuh-indexer/opensearch-security/ \
   -nhnv \
   -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
   -cert /usr/share/wazuh-indexer/certs/admin.pem \
   -key /usr/share/wazuh-indexer/certs/admin-key.pem \
   -icl -p 9200"

docker restart socstack-wazuh-indexer && sleep 30 && docker restart socstack-wazuh-dashboard
```

### SSO redirect loop (302 loop after Keycloak login)

**Cause:** `client_secret` in `opensearch_dashboards.yml` is still a placeholder (`WILL_BE_SET_BY_POST_DEPLOY`).

```bash
# Check if placeholder exists
grep "WILL_BE_SET_BY_POST_DEPLOY" /opt/socstack/configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml

# Fix: re-run post-deploy.py (step 6 injects the secret)
python3 /opt/socstack/post-deploy.py
```

### Wazuh custom-n8n "Couldn't execute command"

**Cause:** Windows CRLF line endings (`\r\n`). `#!/bin/sh\r` is an invalid interpreter.

```bash
# Fix on host (bind-mounted files)
sed -i 's/\r$//' /opt/socstack/configs/wazuh/wazuh_cluster/custom-n8n \
                 /opt/socstack/configs/wazuh/wazuh_cluster/custom-n8n.py
docker restart socstack-wazuh-manager

# Verify
docker exec socstack-wazuh-manager head -1 /var/ossec/integrations/custom-n8n | cat -A
# Should show: #!/bin/sh$  (NOT #!/bin/sh^M$)
```

### Wazuh Indexer crash loop (cert errors)

**Cause 1:** Cert permissions. Generator creates files as `400` (owner-only), containers can't read.
```bash
chmod 444 /opt/socstack/configs/wazuh/wazuh_indexer_ssl_certs/*.pem \
          /opt/socstack/configs/wazuh/wazuh_indexer_ssl_certs/*.key
docker restart socstack-wazuh-indexer
```

**Cause 2:** Cert path mismatch. `wazuh.indexer.yml` paths must match docker-compose mount targets.
```
# Correct paths (docker-compose mounts to /usr/share/wazuh-indexer/certs/):
plugins.security.ssl.http.pemcert_filepath: /usr/share/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /usr/share/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
```

### Cortex HTTP 500 (elasticsearch host)

**Cause:** `cortex-application.conf` uses `elasticsearch` instead of `socstack-elasticsearch`.

```bash
# Fix
sed -i 's|elasticsearch:9200|socstack-elasticsearch:9200|g' \
  /opt/socstack/configs/thehive/cortex-application.conf
docker restart socstack-cortex
```

### docker-compose mount error "not a directory"

**Cause:** Config file missing from deploy dir → Docker creates a directory stub instead.

```bash
# Check which files are directories instead of files
ls -la /opt/socstack/configs/wazuh/wazuh_indexer/

# Fix: copy the correct file, remove directory stub
rm -rf /opt/socstack/configs/wazuh/wazuh_indexer/wazuh.indexer.yml  # remove dir
# Copy the correct file from source, then docker compose up -d
```

### Wazuh Indexer "Not yet initialized"

```bash
docker exec -it socstack-wazuh-indexer bash
/usr/share/wazuh-indexer/bin/indexer-security-init.sh
```

### n8n owner reset

```bash
docker exec socstack-n8n n8n user-management:reset
docker restart socstack-n8n
# Visit UI to create a new owner
```

### Container won't start

```bash
docker logs socstack-<name> --tail 100
docker inspect socstack-<name> --format='{{.State.ExitCode}} {{.State.Error}}'
```

### Out of disk space

```bash
df -h /opt/socstack
du -sh /opt/socstack/data/*
docker system prune -f    # Safe — only removes unused images/containers
```

---

## Known Issues & Fixes

These issues have been identified and are handled automatically by the deployment scripts:

| Issue | Root Cause | Handled By |
|-------|-----------|------------|
| Windows CRLF line endings break scripts | Files SCP'd from Windows have `\r\n` | `pre-deploy.sh` section 6b auto-converts all files |
| Wazuh cert generator v0.0.4 broken | Wazuh removed download URL from packages.wazuh.com | Uses `v0.0.2` instead |
| Cert permissions (400) block containers | Generator creates files with random UID, mode 400 | `pre-deploy.sh` sets `chmod 444` |
| Keycloak gzip theme cache fails | Volume mount creates root-owned dir, Keycloak needs uid 1000 | `pre-deploy.sh` + `post-deploy.py` fix ownership |
| SSO client_secret placeholder not replaced | Race condition if post-deploy step 6 fails | `post-deploy.py` step 7 has safety check + re-injection |
| Cortex hostname mismatch | Config has `elasticsearch` instead of `socstack-elasticsearch` | Fixed in `cortex-application.conf` |
| Wazuh indexer cert path mismatch | Config paths don't match docker-compose mount targets | Fixed in `wazuh.indexer.yml` |

---

## Re-Deployment / Updates

`post-deploy.py` is **idempotent** — safe to re-run any number of times:

| Component | On Re-run |
|-----------|-----------|
| NPM proxy hosts | Skipped if already exist |
| SSL certificates | Skipped if already exist in NPM (avoids Let's Encrypt rate limits) |
| n8n owner | Skipped if already created |
| Cortex | Skipped if already initialized |
| TheHive | Skipped if password already changed |
| Keycloak SSO | Creates realm/client/users only if missing |
| Wazuh security | Always re-applies (safe) |

### Fresh Re-Deploy

```bash
# 1. Stop everything
cd /opt/socstack && docker compose down

# 2. Copy updated files from local
scp -P YOUR_SSH_PORT -r deploy/* root@YOUR_SERVER_IP:/opt/socstack/

# 3. Run pre-deploy (fixes CRLF, permissions, certs)
sudo /opt/socstack/pre-deploy.sh

# 4. Start stack
docker compose up -d

# 5. Wait 3-5 minutes, then run post-deploy
python3 /opt/socstack/post-deploy.py

# 6. Verify
python3 /opt/socstack/test-stack.py
```

### Deploying from Git (Recommended)

```bash
# Clone directly on server (no CRLF issues)
git clone https://github.com/your-repo/socstack.git /opt/socstack

# .gitattributes ensures LF line endings even on Windows
# Run pre-deploy.sh anyway for certs + permissions
sudo /opt/socstack/pre-deploy.sh
docker compose up -d
python3 /opt/socstack/post-deploy.py
```

---

## Files Reference

| File | Purpose | When to Edit |
|------|---------|-------------|
| `.env.example` | Template with all variables | Never (copy to `.env`) |
| `.env` | Your deployment configuration | Before first deploy |
| `.gitattributes` | Forces LF line endings in Git | Never |
| `pre-deploy.sh` | Pre-deployment checks & setup (30 checks) | Rarely |
| `docker-compose.yml` | All 17 service definitions | When adding/modifying services |
| `post-deploy.py` | Automated post-deploy configuration (9 steps) | When changing automation logic |
| `test-stack.py` | Full test suite (59+ tests) | When adding new tests |
| `test-creds.py` | Credential validation tests (30+ checks) | When adding new creds |
| `ssl-setup.py` | SSL certificate helper | Rarely |
| `cortex-setup.py` | Cortex initialization helper | Rarely |
| `POST-DEPLOY-UI-GUIDE.md` | Shareable manual UI config guide (A-E) | When adding UI steps |
| `configs/wazuh/certs.yml` | Wazuh cert generator hostnames | Before generating certs |
| `configs/wazuh/wazuh_indexer/config.yml` | OpenSearch security (OpenID) | When changing SSO |
| `configs/wazuh/wazuh_indexer/roles.yml` | Role definitions | When adding custom roles |
| `configs/wazuh/wazuh_indexer/roles_mapping.yml` | Group → role mappings | When adding SSO groups |
| `configs/wazuh/wazuh_dashboard/opensearch_dashboards.yml` | Dashboard OIDC config | When changing SSO |
| `configs/wazuh/wazuh_cluster/wazuh_manager.conf` | Manager config + integrations | When modifying Wazuh rules |
| `configs/wazuh/wazuh_cluster/custom-n8n` | Webhook integration shell wrapper | Rarely |
| `configs/wazuh/wazuh_cluster/custom-n8n.py` | Webhook integration Python script | When modifying alert payload |
| `configs/n8n/1_Wazuh_Email_Alert.json` | n8n workflow definition | Import via n8n UI |
| `configs/thehive/cortex-application.conf` | Cortex app config | When changing Cortex settings |

---

## Network Architecture

All 17 containers communicate over a single Docker bridge network:

```
socstack_net (172.x.x.0/16)
│
├── socstack-nginx              → proxies all external HTTPS traffic
├── socstack-keycloak           → SSO provider (browser + Wazuh indexer)
├── socstack-keycloak-db        → Keycloak PostgreSQL (internal only)
│
├── socstack-wazuh-manager      → receives agent logs (1514, 1515, 514)
│   └── custom-n8n integration  → forwards alerts to n8n webhook
├── socstack-wazuh-indexer      → stores + indexes security data (hostname: wazuh.indexer)
├── socstack-wazuh-dashboard    → web UI with SSO (proxied through NPM)
│
├── socstack-thehive            → case management (Cassandra + ES + MinIO + Cortex)
├── socstack-cortex             → observable analysis (ES + Docker socket)
├── socstack-cassandra          → TheHive primary database
├── socstack-elasticsearch      → TheHive + Cortex search index
├── socstack-minio              → TheHive S3 file storage
│
├── socstack-misp-core          → threat intelligence platform
├── socstack-misp-db            → MISP MariaDB
├── socstack-misp-redis         → MISP cache (Valkey)
├── socstack-misp-modules       → MISP enrichment modules
│
├── socstack-n8n                → workflow automation (receives Wazuh webhooks)
└── socstack-n8n-redis          → n8n job queue
```

Internal service discovery uses Docker hostnames (e.g., `wazuh.indexer:9200`, `socstack-thehive:9000`).

---

## License

Internal use. All third-party components retain their original licenses.
