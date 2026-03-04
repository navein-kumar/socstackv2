#!/bin/bash
# ============================================================
# SOC STACK - Pre-Deployment Checks & Setup
# ============================================================
# Run this BEFORE docker-compose up -d
# Checks: DNS, Docker, sysctl, folders, permissions
#
# Usage:
#   chmod +x pre-deploy.sh
#   sudo ./pre-deploy.sh
# ============================================================

# CRLF self-fix: single-line so it works even when this file has \r\n endings.
# The trailing # absorbs the \r so bash can parse the line correctly.
grep -qP '\r$' "$0" 2>/dev/null && sed -i 's/\r$//' "$0" && echo "Fixed CRLF in $0 — re-running..." && exec bash "$0" "$@" #

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

ok()   { echo -e "  ${GREEN}✓${NC} $1"; ((PASS++)); }
fail() { echo -e "  ${RED}✗${NC} $1"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; ((WARN++)); }
info() { echo -e "  ${CYAN}→${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

echo "============================================================"
echo "  SOC STACK - Pre-Deployment Checks"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"

# ── Load .env ────────────────────────────────────────────
echo ""
echo "── Loading Configuration ──────────────────────────────"
if [ ! -f "$ENV_FILE" ]; then
    fail ".env file not found at $ENV_FILE"
    echo ""
    info "Copy .env.example to .env and fill in your values:"
    info "  cp .env.example .env"
    info "  nano .env"
    exit 1
fi

# Source env with = parsing (handles values containing = and special chars)
while IFS= read -r line; do
    line=$(echo "$line" | sed 's/\r$//')
    [[ -z "$line" || "$line" == \#* ]] && continue
    key="${line%%=*}"
    value="${line#*=}"
    key=$(echo "$key" | xargs)
    [[ -z "$key" ]] && continue
    value=$(echo "$value" | xargs)
    export "$key=$value"
done < "$ENV_FILE"
ok "Loaded .env"

# Validate required fields
REQUIRED_VARS="SERVER_IP SSO_DOMAIN WAZUH_DOMAIN N8N_DOMAIN MISP_DOMAIN THEHIVE_DOMAIN CORTEX_DOMAIN GRAFANA_DOMAIN NPM_DOMAIN NPM_ADMIN_EMAIL"
for var in $REQUIRED_VARS; do
    val="${!var:-}"
    if [ -z "$val" ] || [[ "$val" == *"YOUR_"* ]] || [[ "$val" == *"yourdomain"* ]] || [[ "$val" == *"ChangeMe"* ]]; then
        fail "$var is not configured (value: ${val:-empty})"
    fi
done

if [ $FAIL -gt 0 ]; then
    echo ""
    fail "Fix .env configuration before continuing"
    exit 1
fi
ok "All required variables set"

# Auto-detect: use the directory where this script lives as DEPLOY_DIR
# No need to set DEPLOY_DIR in .env — just run the script from your deploy folder
DEPLOY_DIR="$SCRIPT_DIR"
info "DEPLOY_DIR auto-detected: $DEPLOY_DIR"
ALL_DOMAINS="$SSO_DOMAIN $WAZUH_DOMAIN $N8N_DOMAIN $MISP_DOMAIN $THEHIVE_DOMAIN $CORTEX_DOMAIN $GRAFANA_DOMAIN $NPM_DOMAIN"

# ── 1. System Checks ─────────────────────────────────────
echo ""
echo "── 1. System Requirements ─────────────────────────────"

# OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    ok "OS: $PRETTY_NAME"
else
    warn "Could not detect OS"
fi

# Root check
if [ "$EUID" -ne 0 ]; then
    fail "Must run as root (sudo ./pre-deploy.sh)"
    exit 1
fi
ok "Running as root"

# RAM
TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
if [ "$TOTAL_RAM_MB" -ge 14000 ]; then
    ok "RAM: ${TOTAL_RAM_MB}MB (minimum 16GB recommended)"
elif [ "$TOTAL_RAM_MB" -ge 10000 ]; then
    warn "RAM: ${TOTAL_RAM_MB}MB (16GB recommended, may work with swap)"
else
    fail "RAM: ${TOTAL_RAM_MB}MB (minimum 16GB required)"
fi

# Disk
DISK_AVAIL_GB=$(df -BG "$DEPLOY_DIR" 2>/dev/null | awk 'NR==2{gsub(/G/,""); print $4}')
[ -z "$DISK_AVAIL_GB" ] && DISK_AVAIL_GB=$(df -BG / 2>/dev/null | awk 'NR==2{gsub(/G/,""); print $4}')
[ -z "$DISK_AVAIL_GB" ] && DISK_AVAIL_GB=0
if [ "$DISK_AVAIL_GB" -ge 80 ]; then
    ok "Disk: ${DISK_AVAIL_GB}GB available (100GB recommended)"
elif [ "$DISK_AVAIL_GB" -ge 50 ]; then
    warn "Disk: ${DISK_AVAIL_GB}GB available (100GB recommended)"
else
    fail "Disk: ${DISK_AVAIL_GB}GB available (minimum 50GB required)"
fi

# ── 2. Docker ─────────────────────────────────────────────
echo ""
echo "── 2. Docker ──────────────────────────────────────────"

if command -v docker &>/dev/null; then
    DOCKER_VER=$(docker --version | grep -oP '\d+\.\d+\.\d+')
    ok "Docker: v${DOCKER_VER}"
else
    fail "Docker not installed"
    info "Install: curl -fsSL https://get.docker.com | sh"
fi

if command -v docker-compose &>/dev/null || docker compose version &>/dev/null 2>&1; then
    COMPOSE_VER=$(docker compose version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' || docker-compose --version | grep -oP '\d+\.\d+\.\d+')
    ok "Docker Compose: v${COMPOSE_VER}"
else
    fail "Docker Compose not installed"
fi

if systemctl is-active --quiet docker 2>/dev/null; then
    ok "Docker daemon running"
else
    fail "Docker daemon not running"
    info "Start: systemctl start docker"
fi

# ── 3. Sysctl Settings ───────────────────────────────────
echo ""
echo "── 3. Kernel Parameters ───────────────────────────────"

MAX_MAP=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [ "$MAX_MAP" -ge 262144 ]; then
    ok "vm.max_map_count = $MAX_MAP"
else
    warn "vm.max_map_count = $MAX_MAP (needs 262144)"
    info "Fixing..."
    sysctl -w vm.max_map_count=262144 >/dev/null 2>&1
    grep -q "vm.max_map_count" /etc/sysctl.conf 2>/dev/null || echo "vm.max_map_count=262144" >> /etc/sysctl.conf
    ok "vm.max_map_count set to 262144 (persistent)"
fi

# ── 4. Ports ──────────────────────────────────────────────
echo ""
echo "── 4. Port Availability ───────────────────────────────"

REQUIRED_PORTS="80 443 1514 1515 514 5601 8081 8443 9000 9001 9002 9200 55000 5678 3000 60081"
for port in $REQUIRED_PORTS; do
    if ss -tlnp | grep -q ":${port} " 2>/dev/null; then
        PROC=$(ss -tlnp | grep ":${port} " | awk '{print $NF}' | head -1)
        warn "Port $port in use by $PROC"
    fi
done
ok "Port check complete"

# ── 5. DNS Resolution ────────────────────────────────────
echo ""
echo "── 5. DNS Resolution ──────────────────────────────────"
info "Checking all domains resolve to ${SERVER_IP}..."

DNS_OK=0
DNS_FAIL=0
for domain in $ALL_DOMAINS; do
    RESOLVED=$(dig +short "$domain" A 2>/dev/null | head -1)
    if [ "$RESOLVED" = "$SERVER_IP" ]; then
        ok "$domain → $RESOLVED"
        ((DNS_OK++))
    elif [ -n "$RESOLVED" ]; then
        fail "$domain → $RESOLVED (expected $SERVER_IP)"
        ((DNS_FAIL++))
    else
        fail "$domain → no DNS record found"
        ((DNS_FAIL++))
    fi
done

if [ "$DNS_FAIL" -gt 0 ]; then
    echo ""
    warn "$DNS_FAIL domain(s) not resolving to $SERVER_IP"
    info "Add DNS A records pointing all domains to $SERVER_IP"
    info "SSL certificates require valid DNS records"
fi

# ── 6. Create Directory Structure ─────────────────────────
echo ""
echo "── 6. Directory Structure ─────────────────────────────"

mkdir -p "$DEPLOY_DIR"
ok "Deploy dir: $DEPLOY_DIR"

# Data directories
DATA_DIRS=(
    "data/nginx/data"
    "data/nginx/letsencrypt"
    "data/keycloak_postgres"
    "data/keycloak_data"
    "data/keycloak_data/tmp"
    "data/thehive/cassandra_data"
    "data/thehive/cassandra_logs"
    "data/thehive/elasticsearch_data"
    "data/thehive/elasticsearch_logs"
    "data/thehive/minio_data"
    "data/thehive/thehive_data"
    "data/thehive/thehive_files"
    "data/thehive/thehive_index"
    "data/thehive/thehive_logs"
    "data/thehive/cortex_logs"
    "data/misp/configs"
    "data/misp/logs"
    "data/misp/files"
    "data/misp/ssl"
    "data/misp/gnupg"
    "data/misp/mysql_data"
    "data/n8n"
    "data/n8n_redis"
    "data/grafana"
)

for dir in "${DATA_DIRS[@]}"; do
    mkdir -p "$DEPLOY_DIR/$dir"
done
ok "Created ${#DATA_DIRS[@]} data directories"

# Config directories
CONFIG_DIRS=(
    "configs/wazuh/wazuh_indexer"
    "configs/wazuh/wazuh_indexer_ssl_certs"
    "configs/wazuh/wazuh_dashboard"
    "configs/wazuh/wazuh_cluster"
    "configs/thehive"
    "configs/grafana/provisioning/datasources"
    "configs/grafana/provisioning/dashboards"
    "configs/grafana/dashboards"
)

for dir in "${CONFIG_DIRS[@]}"; do
    mkdir -p "$DEPLOY_DIR/$dir"
done
ok "Created config directories"

# ── 6b. Fix Windows CRLF line endings ────────────────────
# Files SCP'd from Windows have \r\n — Linux scripts/configs need \n
# This covers EVERY text file in the deploy directory — configs, scripts, docs, env, compose, everything
info "Fixing Windows CRLF line endings on ALL text files..."
CRLF_FIXED=0
CRLF_SCANNED=0

# Single comprehensive find: ALL text file types across entire deploy dir (excluding data/ and .git/)
while IFS= read -r f; do
    ((CRLF_SCANNED++))
    if grep -qP '\r$' "$f" 2>/dev/null; then
        sed -i 's/\r$//' "$f"
        ((CRLF_FIXED++))
    fi
done < <(find "$DEPLOY_DIR" -type f \
    \( -name "*.sh" -o -name "*.py" -o -name "*.yml" -o -name "*.yaml" \
    -o -name "*.conf" -o -name "*.xml" -o -name "*.json" -o -name "*.md" \
    -o -name "*.env" -o -name "*.env.*" -o -name "*.example" \
    -o -name "*.gitignore" -o -name "*.gitattributes" \
    -o -name "docker-compose.yml" -o -name "docker-compose.yaml" \) \
    ! -path "*/data/*" ! -path "*/.git/*" 2>/dev/null)

# Also fix files with NO extension (shell wrappers like custom-n8n)
while IFS= read -r f; do
    ((CRLF_SCANNED++))
    if grep -qP '\r$' "$f" 2>/dev/null; then
        sed -i 's/\r$//' "$f"
        ((CRLF_FIXED++))
    fi
done < <(find "$DEPLOY_DIR/configs" -type f ! -name "*.*" 2>/dev/null)

if [ "$CRLF_FIXED" -gt 0 ]; then
    ok "Fixed CRLF → LF in $CRLF_FIXED of $CRLF_SCANNED file(s)"
else
    ok "All $CRLF_SCANNED text files clean (no CRLF found)"
fi

# ── 7. Fix Permissions ────────────────────────────────────
echo ""
echo "── 7. Permissions ─────────────────────────────────────"

# Keycloak runs as uid 1000 — needs writable data dir for gzip theme cache
chown -R 1000:0 "$DEPLOY_DIR/data/keycloak_data"
ok "Keycloak data dir: uid 1000 (gzip theme cache)"

# Grafana runs as uid 472
chown -R 472:0 "$DEPLOY_DIR/data/grafana"
ok "Grafana data dir: uid 472"

# Grafana OpenSearch datasource plugin (download if not present)
GF_PLUGIN_DIR="$DEPLOY_DIR/data/grafana/plugins/grafana-opensearch-datasource"
if [ ! -d "$GF_PLUGIN_DIR" ]; then
    info "Downloading Grafana OpenSearch datasource plugin..."
    GF_PLUGIN_URL="https://github.com/grafana/opensearch-datasource/releases/download/v2.22.1/grafana-opensearch-datasource-2.22.1.linux_amd64.zip"
    mkdir -p "$DEPLOY_DIR/data/grafana/plugins"
    if curl -sL -o /tmp/grafana-opensearch-plugin.zip "$GF_PLUGIN_URL" 2>/dev/null; then
        unzip -qo /tmp/grafana-opensearch-plugin.zip -d "$DEPLOY_DIR/data/grafana/plugins/" 2>/dev/null
        rm -f /tmp/grafana-opensearch-plugin.zip
        chown -R 472:0 "$DEPLOY_DIR/data/grafana/plugins/"
        ok "Grafana OpenSearch plugin installed"
    else
        warn "Could not download Grafana OpenSearch plugin (check internet/DNS)"
    fi
else
    ok "Grafana OpenSearch plugin already installed"
fi

# TheHive/Cortex dirs
chown -R 1000:1000 "$DEPLOY_DIR/data/thehive/thehive_data" "$DEPLOY_DIR/data/thehive/thehive_files" "$DEPLOY_DIR/data/thehive/thehive_index" 2>/dev/null || true
ok "TheHive data dirs: uid 1000"

# Elasticsearch (uid 1000)
chown -R 1000:1000 "$DEPLOY_DIR/data/thehive/elasticsearch_data" "$DEPLOY_DIR/data/thehive/elasticsearch_logs" 2>/dev/null || true
ok "Elasticsearch data dir: uid 1000"

# n8n runs as uid 1000 (node) — needs writable data dir for config/encryption key
chown -R 1000:1000 "$DEPLOY_DIR/data/n8n"
ok "n8n data dir: uid 1000"

# Wazuh custom integration scripts (custom-n8n) — must match /var/ossec/integrations/slack permissions
# Inside container: owner root, group wazuh (gid 101), mode 750
N8N_INTEGRATION_DIR="$DEPLOY_DIR/configs/wazuh/wazuh_cluster"
if [ -f "$N8N_INTEGRATION_DIR/custom-n8n" ] && [ -f "$N8N_INTEGRATION_DIR/custom-n8n.py" ]; then
    # Fix Windows CRLF line endings → Unix LF (critical: #!/bin/sh\r breaks execution)
    sed -i 's/\r$//' "$N8N_INTEGRATION_DIR/custom-n8n" "$N8N_INTEGRATION_DIR/custom-n8n.py"
    ok "custom-n8n: CRLF → LF line endings fixed"
    chmod 750 "$N8N_INTEGRATION_DIR/custom-n8n" "$N8N_INTEGRATION_DIR/custom-n8n.py"
    ok "custom-n8n integration scripts: mode 750"
else
    warn "custom-n8n integration scripts not found in $N8N_INTEGRATION_DIR"
fi

# ── 8. Wazuh SSL Certificates (auto-generate if missing) ─
echo ""
echo "── 8. Wazuh SSL Certificates ──────────────────────────"

CERT_DIR="$DEPLOY_DIR/configs/wazuh/wazuh_indexer_ssl_certs"
CERTS_YML="$DEPLOY_DIR/configs/wazuh/certs.yml"
REQUIRED_CERTS="root-ca.pem admin.pem admin-key.pem wazuh.indexer.pem wazuh.indexer-key.pem wazuh.manager.pem wazuh.manager-key.pem wazuh.dashboard.pem wazuh.dashboard-key.pem"

mkdir -p "$CERT_DIR"

CERTS_FOUND=0
CERTS_MISSING=0
for cert in $REQUIRED_CERTS; do
    if [ -f "$CERT_DIR/$cert" ]; then
        ((CERTS_FOUND++))
    else
        ((CERTS_MISSING++))
    fi
done

if [ "$CERTS_MISSING" -eq 0 ]; then
    ok "All $CERTS_FOUND Wazuh SSL certificates present"
else
    info "$CERTS_MISSING certificate(s) missing — auto-generating..."

    # Check certs.yml exists
    if [ ! -f "$CERTS_YML" ]; then
        # Create default certs.yml
        cat > "$CERTS_YML" << 'CERTYML'
nodes:
  indexer:
    - name: wazuh.indexer
      ip: wazuh.indexer
  server:
    - name: wazuh.manager
      ip: wazuh.manager
  dashboard:
    - name: wazuh.dashboard
      ip: wazuh.dashboard
CERTYML
        ok "Created default certs.yml"
    fi

    # Generate certs using Wazuh cert generator Docker image (v0.0.4 for Wazuh 4.14.x)
    info "Running wazuh-certs-generator v0.0.4 (Docker)..."
    docker run --rm \
        -e CERT_TOOL_VERSION=4.14 \
        -v "$CERT_DIR":/certificates/ \
        -v "$CERTS_YML":/config/certs.yml \
        wazuh/wazuh-certs-generator:0.0.4 2>&1 | tail -5

    if [ $? -eq 0 ]; then
        # Verify generation worked
        GEN_OK=0
        GEN_FAIL=0
        for cert in $REQUIRED_CERTS; do
            if [ -f "$CERT_DIR/$cert" ]; then
                ((GEN_OK++))
            else
                ((GEN_FAIL++))
            fi
        done

        # Create root-ca-manager.pem (copy of root-ca.pem, needed by manager mount)
        if [ -f "$CERT_DIR/root-ca.pem" ] && [ ! -f "$CERT_DIR/root-ca-manager.pem" ]; then
            cp "$CERT_DIR/root-ca.pem" "$CERT_DIR/root-ca-manager.pem"
        fi

        if [ "$GEN_FAIL" -eq 0 ]; then
            ok "Generated all $GEN_OK Wazuh SSL certificates"
        else
            fail "$GEN_FAIL certificate(s) still missing after generation"
            info "Check Docker logs above for errors"
        fi
    else
        fail "Certificate generation failed"
        info "Manual generation:"
        info "  docker run --rm -e CERT_TOOL_VERSION=4.14 -v $CERT_DIR:/certificates/ -v $CERTS_YML:/config/certs.yml wazuh/wazuh-certs-generator:0.0.4"
    fi
fi

# Copy system CA bundle → system-ca.pem (bind-mounted into indexer for OIDC/SSO trust)
# This file must exist on the HOST before docker-compose up, as it is bind-mounted
# The indexer uses it to verify Keycloak's SSL cert during SSO token validation
SYSTEM_CA_SRC="/etc/ssl/certs/ca-certificates.crt"
SYSTEM_CA_DST="$CERT_DIR/system-ca.pem"
if [ -f "$SYSTEM_CA_SRC" ]; then
    cp "$SYSTEM_CA_SRC" "$SYSTEM_CA_DST"
    ok "system-ca.pem created from $SYSTEM_CA_SRC (for OIDC/SSO trust)"
elif [ ! -f "$SYSTEM_CA_DST" ]; then
    warn "system-ca.pem not found — SSO login may fail (no /etc/ssl/certs/ca-certificates.crt)"
fi

# Fix cert permissions — generator creates as 400 with random UID
# Docker containers need to read these certs (bind-mounted)
if [ -d "$CERT_DIR" ]; then
    chmod 444 "$CERT_DIR"/*.pem "$CERT_DIR"/*.key 2>/dev/null
    chmod 755 "$CERT_DIR"
    ok "Wazuh SSL cert permissions: 444 (world-readable)"
fi

# ── Summary ───────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  PRE-DEPLOY CHECK SUMMARY"
echo "============================================================"
echo -e "  ${GREEN}Passed:${NC} $PASS"
echo -e "  ${RED}Failed:${NC} $FAIL"
echo -e "  ${YELLOW}Warned:${NC} $WARN"
echo "============================================================"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo -e "  ${RED}FIX FAILURES BEFORE DEPLOYING${NC}"
    echo ""
    exit 1
else
    echo ""
    echo -e "  ${GREEN}ALL CHECKS PASSED — Ready to deploy!${NC}"
    echo ""
    echo "  Next steps:"
    echo "    1. Copy files to server:  scp -r deploy/* root@${SERVER_IP}:${DEPLOY_DIR}/"
    echo "    2. Start the stack:       cd ${DEPLOY_DIR} && docker compose up -d"
    echo "    3. Wait 2-3 minutes for all services to start"
    echo "    4. Run post-deploy:       python3 ${DEPLOY_DIR}/post-deploy.py"
    echo "    5. Run tests:             python3 ${DEPLOY_DIR}/test-stack.py"
    echo ""
fi
