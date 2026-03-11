#!/bin/bash
# ============================================================
# SOC STACK (IP-SSL) - Pre-Deployment Checks & Setup
# ============================================================
# Run this BEFORE docker-compose up -d
# Checks: Docker, sysctl, folders, permissions, cert generation
# NO DNS checks — IP-based mode uses self-signed SSL
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
echo "  SOC STACK (IP-SSL) - Pre-Deployment Checks"
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
REQUIRED_VARS="SERVER_IP"
for var in $REQUIRED_VARS; do
    val="${!var:-}"
    if [ -z "$val" ] || [[ "$val" == *"YOUR_"* ]]; then
        fail "$var is not configured (value: ${val:-empty})"
    fi
done

if [ $FAIL -gt 0 ]; then
    echo ""
    fail "Fix .env configuration before continuing"
    exit 1
fi
ok "SERVER_IP = ${SERVER_IP}"

# Load port defaults
WAZUH_PORT="${WAZUH_PORT:-8443}"
SSO_PORT="${SSO_PORT:-8444}"
N8N_PORT="${N8N_PORT:-8445}"
MISP_PORT="${MISP_PORT:-8446}"
THEHIVE_PORT="${THEHIVE_PORT:-8447}"
CORTEX_PORT="${CORTEX_PORT:-8448}"

# Auto-detect: use the directory where this script lives as DEPLOY_DIR
# No need to set DEPLOY_DIR in .env — just run the script from your deploy folder
DEPLOY_DIR="$SCRIPT_DIR"
info "DEPLOY_DIR auto-detected: $DEPLOY_DIR"

# ── Auto-generate SSO secrets (if not already set in .env) ──
# These are needed BEFORE docker-compose up so oauth2-proxy containers
# start with the correct secrets on first boot — no post-deploy dependency
echo ""
echo "── SSO Secrets ────────────────────────────────────────"

if [ -z "${SSO_CLIENT_SECRET:-}" ] || [ "$SSO_CLIENT_SECRET" = "CHANGE_ME" ]; then
    SSO_CLIENT_SECRET=$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)
    # Append or update in .env
    if grep -q '^SSO_CLIENT_SECRET=' "$ENV_FILE" 2>/dev/null; then
        sed -i "s|^SSO_CLIENT_SECRET=.*|SSO_CLIENT_SECRET=${SSO_CLIENT_SECRET}|" "$ENV_FILE"
    else
        echo "SSO_CLIENT_SECRET=${SSO_CLIENT_SECRET}" >> "$ENV_FILE"
    fi
    ok "SSO_CLIENT_SECRET auto-generated and saved to .env"
else
    ok "SSO_CLIENT_SECRET already set: ${SSO_CLIENT_SECRET:0:8}..."
fi

if [ -z "${OAUTH2_PROXY_COOKIE_SECRET:-}" ] || [ "$OAUTH2_PROXY_COOKIE_SECRET" = "CHANGE_ME" ]; then
    # Must be exactly 16, 24, or 32 bytes for AES cipher (oauth2-proxy v7.x)
    # openssl rand -hex 16 = 32 hex chars = 32 bytes as raw string
    OAUTH2_PROXY_COOKIE_SECRET=$(openssl rand -hex 16)
    if grep -q '^OAUTH2_PROXY_COOKIE_SECRET=' "$ENV_FILE" 2>/dev/null; then
        sed -i "s|^OAUTH2_PROXY_COOKIE_SECRET=.*|OAUTH2_PROXY_COOKIE_SECRET=${OAUTH2_PROXY_COOKIE_SECRET}|" "$ENV_FILE"
    else
        echo "OAUTH2_PROXY_COOKIE_SECRET=${OAUTH2_PROXY_COOKIE_SECRET}" >> "$ENV_FILE"
    fi
    ok "OAUTH2_PROXY_COOKIE_SECRET auto-generated and saved to .env"
else
    ok "OAUTH2_PROXY_COOKIE_SECRET already set: ${OAUTH2_PROXY_COOKIE_SECRET:0:12}..."
fi

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

# Check openssl is available (needed for cert generation)
if command -v openssl &>/dev/null; then
    OPENSSL_VER=$(openssl version | awk '{print $2}')
    ok "OpenSSL: v${OPENSSL_VER}"
else
    fail "OpenSSL not installed (required for self-signed cert generation)"
    info "Install: apt-get install openssl  OR  yum install openssl"
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

REQUIRED_PORTS="1514 1515 514 5601 8081 9000 9001 9002 9200 55000 5678 ${WAZUH_PORT} ${SSO_PORT} ${N8N_PORT} ${MISP_PORT} ${THEHIVE_PORT} ${CORTEX_PORT}"
for port in $REQUIRED_PORTS; do
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        PROC=$(ss -tlnp 2>/dev/null | grep ":${port} " | awk '{print $NF}' | head -1)
        warn "Port $port in use by $PROC"
    fi
done
ok "Port check complete (service ports: ${WAZUH_PORT}, ${SSO_PORT}, ${N8N_PORT}, ${MISP_PORT}, ${THEHIVE_PORT}, ${CORTEX_PORT})"

# ── 5. Create Directory Structure ─────────────────────────
echo ""
echo "── 5. Directory Structure ─────────────────────────────"

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
)

for dir in "${CONFIG_DIRS[@]}"; do
    mkdir -p "$DEPLOY_DIR/$dir"
done
ok "Created config directories"

# ── 5b. Fix Windows CRLF line endings ────────────────────
info "Fixing Windows CRLF line endings on ALL text files..."
CRLF_FIXED=0
CRLF_SCANNED=0

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
    -o -name "docker-compose.yml" -o -name "docker-compose.yaml" \) \
    ! -path "*/data/*" ! -path "*/.git/*" 2>/dev/null)

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

# ── 6. Fix Permissions ────────────────────────────────────
echo ""
echo "── 6. Permissions ─────────────────────────────────────"

chown -R 1000:0 "$DEPLOY_DIR/data/keycloak_data"
ok "Keycloak data dir: uid 1000"

chown -R 1000:1000 "$DEPLOY_DIR/data/thehive/thehive_data" "$DEPLOY_DIR/data/thehive/thehive_files" "$DEPLOY_DIR/data/thehive/thehive_index" 2>/dev/null || true
ok "TheHive data dirs: uid 1000"

chown -R 1000:1000 "$DEPLOY_DIR/data/thehive/elasticsearch_data" "$DEPLOY_DIR/data/thehive/elasticsearch_logs" 2>/dev/null || true
ok "Elasticsearch data dir: uid 1000"

chown -R 1000:1000 "$DEPLOY_DIR/data/n8n"
ok "n8n data dir: uid 1000"

# Wazuh custom integration scripts
N8N_INTEGRATION_DIR="$DEPLOY_DIR/configs/wazuh/wazuh_cluster"
if [ -f "$N8N_INTEGRATION_DIR/custom-n8n" ] && [ -f "$N8N_INTEGRATION_DIR/custom-n8n.py" ]; then
    sed -i 's/\r$//' "$N8N_INTEGRATION_DIR/custom-n8n" "$N8N_INTEGRATION_DIR/custom-n8n.py"
    ok "custom-n8n: CRLF → LF line endings fixed"
    # Wazuh manager runs custom integrations as root:wazuh (gid 101) with mode 750
    # Set this on the host so bind-mounted files have correct ownership from first boot
    chown 0:101 "$N8N_INTEGRATION_DIR/custom-n8n" "$N8N_INTEGRATION_DIR/custom-n8n.py"
    chmod 750 "$N8N_INTEGRATION_DIR/custom-n8n" "$N8N_INTEGRATION_DIR/custom-n8n.py"
    ok "custom-n8n integration: root:wazuh(101) mode 750"
else
    warn "custom-n8n integration scripts not found in $N8N_INTEGRATION_DIR"
fi

# ── 7. Self-Signed SSL Certificate Generation ─────────────
echo ""
echo "── 7. Self-Signed SSL Certificates ───────────────────"

CERT_DIR="$DEPLOY_DIR/certs"
mkdir -p "$CERT_DIR"

# ── Docker mount cleanup ──
# If docker-compose was run before certs existed, Docker creates bind-mount
# source paths as DIRECTORIES (not files). OpenSSL silently fails trying to
# write a file where a directory exists. Detect and remove stale directories.
CERT_FILES_EXPECTED="ca.key ca.crt server.key server.crt"
for f in $CERT_FILES_EXPECTED; do
    if [ -d "$CERT_DIR/$f" ]; then
        warn "$CERT_DIR/$f is a stale Docker-created directory — removing"
        rm -rf "$CERT_DIR/$f"
    fi
done
# Also clean any leftover serial/csr files from partial runs
rm -f "$CERT_DIR/ca.srl" "$CERT_DIR/server.csr"

# Check if valid certs already exist for this IP
CERTS_OK=true
for f in ca.key ca.crt server.key server.crt; do
    [ ! -f "$CERT_DIR/$f" ] && CERTS_OK=false && break
done

if [ "$CERTS_OK" = true ]; then
    # Verify the existing cert covers the current SERVER_IP
    CERT_IP=$(openssl x509 -in "$CERT_DIR/server.crt" -noout -text 2>/dev/null | grep -oP 'IP Address:\K[0-9.]+' | head -1)
    if [ "$CERT_IP" = "$SERVER_IP" ]; then
        ok "Self-signed certificates already exist for IP ${SERVER_IP} — skipping generation"
    else
        warn "Existing cert is for IP ${CERT_IP}, but SERVER_IP is ${SERVER_IP} — regenerating..."
        CERTS_OK=false
    fi
fi

if [ "$CERTS_OK" = false ]; then
    info "Generating self-signed CA and server certificate for IP: ${SERVER_IP}"

    # Clean any partial files from a previous failed run
    rm -f "$CERT_DIR/ca.key" "$CERT_DIR/ca.crt" "$CERT_DIR/server.key" "$CERT_DIR/server.crt" "$CERT_DIR/server.csr" "$CERT_DIR/ca.srl"

    # Step 1: Generate CA private key + self-signed CA certificate (10 years)
    if ! openssl genrsa -out "$CERT_DIR/ca.key" 2048 2>&1 | tail -1; then
        fail "CA key generation failed"
    fi
    if ! openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 3650 \
        -out "$CERT_DIR/ca.crt" \
        -subj "/C=US/ST=Lab/L=Lab/O=SOC-Stack/OU=Security/CN=SOC-Stack-CA" 2>&1; then
        fail "CA certificate generation failed"
    fi

    if [ -f "$CERT_DIR/ca.crt" ]; then
        ok "CA certificate generated (valid 10 years)"
    else
        fail "CA certificate file not created — check OpenSSL output above"
    fi

    # Step 2: Create OpenSSL extension config with IP SAN
    cat > "$CERT_DIR/server-ext.cnf" << EOF
[req]
default_bits       = 2048
prompt             = no
distinguished_name = dn
req_extensions     = v3_req

[dn]
C  = US
ST = Lab
L  = Lab
O  = SOC-Stack
OU = Security
CN = ${SERVER_IP}

[v3_req]
basicConstraints     = CA:FALSE
keyUsage             = digitalSignature, keyEncipherment
extendedKeyUsage     = serverAuth, clientAuth
subjectAltName       = @alt_names

[alt_names]
IP.1 = ${SERVER_IP}
IP.2 = 127.0.0.1
EOF

    # Step 3: Generate server key + CSR
    if ! openssl genrsa -out "$CERT_DIR/server.key" 2048 2>&1 | tail -1; then
        fail "Server key generation failed"
    fi
    if ! openssl req -new -key "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.csr" \
        -config "$CERT_DIR/server-ext.cnf" 2>&1; then
        fail "Server CSR generation failed"
    fi

    # Step 4: Sign the CSR with the CA (valid 825 days — Apple device limit)
    if ! openssl x509 -req -in "$CERT_DIR/server.csr" \
        -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
        -out "$CERT_DIR/server.crt" -days 825 -sha256 \
        -extfile "$CERT_DIR/server-ext.cnf" -extensions v3_req 2>&1; then
        fail "Server certificate signing failed"
    fi

    # Verify the SAN is embedded in the signed cert
    if [ -f "$CERT_DIR/server.crt" ]; then
        CERT_SAN=$(openssl x509 -in "$CERT_DIR/server.crt" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name")
        if echo "$CERT_SAN" | grep -q "IP Address:${SERVER_IP}"; then
            ok "Server certificate generated with IP SAN: ${SERVER_IP}"
        else
            fail "Server certificate SAN verification failed"
            info "Debug: $CERT_SAN"
        fi
    else
        fail "Server certificate file not created — check OpenSSL errors above"
    fi

    # Cleanup CSR (not needed after signing)
    rm -f "$CERT_DIR/server.csr"

    # Set permissions
    chmod 400 "$CERT_DIR/ca.key" "$CERT_DIR/server.key" 2>/dev/null
    chmod 444 "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt" 2>/dev/null
    chmod 755 "$CERT_DIR"
    ok "Certificate permissions set (keys: 400, certs: 444)"
fi

# ── 8. Wazuh SSL Certificates (auto-generate if missing) ─
echo ""
echo "── 8. Wazuh SSL Certificates ──────────────────────────"

WAZUH_CERT_DIR="$DEPLOY_DIR/configs/wazuh/wazuh_indexer_ssl_certs"
CERTS_YML="$DEPLOY_DIR/configs/wazuh/certs.yml"
REQUIRED_CERTS="root-ca.pem admin.pem admin-key.pem wazuh.indexer.pem wazuh.indexer-key.pem wazuh.manager.pem wazuh.manager-key.pem wazuh.dashboard.pem wazuh.dashboard-key.pem"

mkdir -p "$WAZUH_CERT_DIR"

# ── Docker mount cleanup ──
# Same issue as self-signed certs: if docker-compose was run before Wazuh
# certs existed, Docker creates bind-mount sources as DIRECTORIES.
# The wazuh-certs-generator then fails with "cp: -r not specified; omitting
# directory" when it tries to write cert files. Remove stale directories.
WAZUH_STALE_CLEANED=0
for cert in $REQUIRED_CERTS root-ca-manager.pem root-ca.key root-ca-manager.key; do
    if [ -d "$WAZUH_CERT_DIR/$cert" ]; then
        warn "$WAZUH_CERT_DIR/$cert is a stale Docker-created directory — removing"
        rm -rf "$WAZUH_CERT_DIR/$cert"
        ((WAZUH_STALE_CLEANED++))
    fi
done
[ "$WAZUH_STALE_CLEANED" -gt 0 ] && info "Cleaned $WAZUH_STALE_CLEANED stale directory(ies) from Wazuh cert dir"

CERTS_FOUND=0
CERTS_MISSING=0
for cert in $REQUIRED_CERTS; do
    if [ -f "$WAZUH_CERT_DIR/$cert" ]; then
        ((CERTS_FOUND++))
    else
        ((CERTS_MISSING++))
    fi
done

if [ "$CERTS_MISSING" -eq 0 ]; then
    ok "All $CERTS_FOUND Wazuh SSL certificates present"
else
    info "$CERTS_MISSING certificate(s) missing — auto-generating..."

    if [ ! -f "$CERTS_YML" ]; then
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

    info "Running wazuh-certs-generator v0.0.4 (Docker)..."
    docker run --rm \
        -e CERT_TOOL_VERSION=4.14 \
        -v "$WAZUH_CERT_DIR":/certificates/ \
        -v "$CERTS_YML":/config/certs.yml \
        wazuh/wazuh-certs-generator:0.0.4 2>&1 | tail -5

    if [ $? -eq 0 ]; then
        GEN_OK=0
        GEN_FAIL=0
        for cert in $REQUIRED_CERTS; do
            if [ -f "$WAZUH_CERT_DIR/$cert" ]; then
                ((GEN_OK++))
            else
                ((GEN_FAIL++))
                info "Missing after generation: $cert"
            fi
        done

        if [ -f "$WAZUH_CERT_DIR/root-ca.pem" ] && [ ! -f "$WAZUH_CERT_DIR/root-ca-manager.pem" ]; then
            cp "$WAZUH_CERT_DIR/root-ca.pem" "$WAZUH_CERT_DIR/root-ca-manager.pem"
        fi

        if [ "$GEN_FAIL" -eq 0 ]; then
            ok "Generated all $GEN_OK Wazuh SSL certificates"
        else
            fail "$GEN_FAIL certificate(s) still missing after generation"
        fi
    else
        fail "Certificate generation failed"
    fi
fi

# Copy self-signed CA as system-ca.pem for Wazuh Indexer OIDC trust
# The Wazuh Indexer needs to trust Keycloak's cert (served via our self-signed CA)
SYSTEM_CA_DST="$WAZUH_CERT_DIR/system-ca.pem"
if [ -f "$CERT_DIR/ca.crt" ]; then
    cp "$CERT_DIR/ca.crt" "$SYSTEM_CA_DST"
    ok "system-ca.pem created from self-signed CA (for OIDC/SSO trust)"
else
    warn "Self-signed CA not found at $CERT_DIR/ca.crt — SSO login may fail"
fi

# Fix cert permissions
if [ -d "$WAZUH_CERT_DIR" ]; then
    chmod 444 "$WAZUH_CERT_DIR"/*.pem "$WAZUH_CERT_DIR"/*.key 2>/dev/null
    chmod 755 "$WAZUH_CERT_DIR"
    ok "Wazuh SSL cert permissions: 444 (world-readable)"
fi

# Create Cortex Java truststore with self-signed CA
# Cortex JVM needs to trust the self-signed CA to call Keycloak's HTTPS
# token/userinfo endpoints during SSO OAuth2 code exchange.
# MUST be created BEFORE docker-compose up — Cortex volume mount expects a FILE,
# not a directory. Docker auto-creates missing mount sources as directories.
CORTEX_CACERTS="$DEPLOY_DIR/configs/thehive/cortex-cacerts"
# Docker mount cleanup: remove stale directory if Docker created it
if [ -d "$CORTEX_CACERTS" ]; then
    warn "cortex-cacerts is a stale Docker-created directory — removing"
    rm -rf "$CORTEX_CACERTS"
fi
if [ -f "$CERT_DIR/ca.crt" ]; then
    if [ -f "$CORTEX_CACERTS" ]; then
        ok "Cortex truststore already exists"
    else
        info "Creating Cortex truststore from Docker image (one-time)..."
        # Use a temporary Cortex container to extract default Java cacerts + import our CA.
        # This avoids needing keytool on the host — uses the container's own JDK tools.
        # --entrypoint sh: override Cortex's entrypoint so sh -c runs properly
        # Convert PEM → DER first (Java 11 keytool can choke on PEM certs)
        openssl x509 -in "$CERT_DIR/ca.crt" -outform DER -out "$CERT_DIR/ca.der"
        docker run --rm --entrypoint sh \
            -v "$(dirname "$CORTEX_CACERTS"):/out" \
            -v "$CERT_DIR/ca.der:/tmp/ca.der:ro" \
            thehiveproject/cortex:3.1.8-1 \
            -c "cp /usr/lib/jvm/java-11-amazon-corretto/lib/security/cacerts /out/cortex-cacerts && \
                keytool -importcert -trustcacerts -alias socstack-ca \
                -file /tmp/ca.der -keystore /out/cortex-cacerts \
                -storepass changeit -noprompt" 2>&1 | tail -3
        rm -f "$CERT_DIR/ca.der"
        if [ -f "$CORTEX_CACERTS" ]; then
            ok "Cortex truststore created with self-signed CA (from container keytool)"
        else
            fail "Cortex truststore creation failed — Cortex SSO will not work"
            info "Manual fix: docker-compose up -d, then:"
            info "  docker cp socstack-cortex:/usr/lib/jvm/java-11-amazon-corretto/lib/security/cacerts ${CORTEX_CACERTS}"
            info "  keytool -importcert -trustcacerts -alias socstack-ca -file ${CERT_DIR}/ca.crt -keystore ${CORTEX_CACERTS} -storepass changeit -noprompt"
        fi
    fi
else
    warn "Self-signed CA not found — Cortex SSO will fail (cannot trust Keycloak HTTPS)"
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
    echo "  Self-signed CA certificate: ${CERT_DIR}/ca.crt"
    echo "  Import this CA into your browser/OS to trust the stack."
    echo ""
    echo "  Access URLs after deployment:"
    echo "    Wazuh Dashboard : https://${SERVER_IP}:${WAZUH_PORT}"
    echo "    Keycloak SSO    : https://${SERVER_IP}:${SSO_PORT}"
    echo "    n8n             : https://${SERVER_IP}:${N8N_PORT}"
    echo "    MISP            : https://${SERVER_IP}:${MISP_PORT}"
    echo "    TheHive         : https://${SERVER_IP}:${THEHIVE_PORT}"
    echo "    Cortex          : https://${SERVER_IP}:${CORTEX_PORT}"
    echo ""
    echo "  Next steps:"
    echo "    1. Copy files to server:  scp -r ip-ssl/* root@${SERVER_IP}:${DEPLOY_DIR}/"
    echo "    2. Start the stack:       cd ${DEPLOY_DIR} && docker compose up -d"
    echo "    3. Wait 2-3 minutes for all services to start"
    echo "    4. Run post-deploy:       python3 ${DEPLOY_DIR}/post-deploy.py"
    echo ""
fi
