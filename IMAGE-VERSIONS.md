# Docker Image Version Map

All images are pinned to exact versions tested on **2026-03-09**.
Do NOT change any image tag to `:latest` — upstream updates can silently break
SSO hooks, config file formats, and internal API compatibility.

## How to Upgrade

1. Check release notes of the target image for breaking changes
2. Update the tag in `docker-compose.yml`
3. Run `docker-compose pull <service>`
4. Run `docker-compose up -d <service>`
5. Re-run `test-stack.py` and `test-creds.py` to confirm nothing broke
6. If SSO breaks, check `docker logs socstack-<service>` for errors

## Pinned Versions

| Service | Image | Version | Notes |
|---------|-------|---------|-------|
| Nginx Proxy Manager | `jc21/nginx-proxy-manager` | `2.14.0` | Reverse proxy + SSL |
| Keycloak SSO | `quay.io/keycloak/keycloak` | `26.5.3` | Central SSO provider |
| Wazuh Manager | `wazuh/wazuh-manager` | `4.14.3` | Via `${WAZUH_VERSION}` in .env |
| Wazuh Indexer | `wazuh/wazuh-indexer` | `4.14.3` | Via `${WAZUH_VERSION}` in .env |
| Wazuh Dashboard | `wazuh/wazuh-dashboard` | `4.14.3` | Via `${WAZUH_VERSION}` in .env |
| TheHive | `strangebee/thehive` | `5.2` | Case management |
| Cortex | `thehiveproject/cortex` | `3.1.8-1` | Analyzer engine |
| Cassandra | `cassandra` | `4.1` | TheHive backend DB |
| Elasticsearch | `docker.elastic.co/.../elasticsearch` | `7.17.15` | Cortex + TheHive index |
| MinIO | `minio/minio` | `RELEASE.2025-09-07T16-13-09Z` | S3 storage for TheHive |
| MISP Core | `ghcr.io/misp/misp-docker/misp-core` | `2.5.32` | Pinned by sha256 digest (no version tags) |
| MISP Modules | `ghcr.io/misp/misp-docker/misp-modules` | `3.0.5` | Pinned by sha256 digest (no version tags) |
| n8n | `docker.n8n.io/n8nio/n8n` | `2.7.5` | Workflow automation + SSO hook |
| oauth2-proxy | `quay.io/oauth2-proxy/oauth2-proxy` | `v7.7.1` | SSO proxy for TheHive + n8n |
| Node.js (hive-bridge) | `node` | `22-alpine` | TheHive SSO bridge |
| Keycloak DB | `postgres` | `15-alpine` | Keycloak backend |
| MISP DB | `mariadb` | `10.11` | MISP backend |
| n8n Redis | `redis` | `7-alpine` | n8n cache |
| MISP Redis | `valkey/valkey` | `7.2` | MISP cache |
| Grafana (domain-ssl only) | `grafana/grafana-oss` | `12.3.3` | Optional monitoring |
| Grafana Renderer | `grafana/grafana-image-renderer` | `3.12.1` | Optional |

## Known Upgrade Risks

| Image | Risk | What Breaks |
|-------|------|-------------|
| **n8n** | HIGH | SSO hook (`hooks.js`) depends on internal TypeORM entities and `issueCookie()`. n8n 2.7+ already broke the User.role relation (v3.2 fix). Future versions may change the hook API entirely. |
| **Keycloak** | MEDIUM | Realm export/import format, admin API endpoints, OIDC token structure. Test SSO on all services after upgrade. |
| **MISP** | MEDIUM | OIDC plugin config keys may change. Test SSO login after upgrade. |
| **Wazuh** | MEDIUM | OpenSearch Security plugin version must match indexer. Always upgrade all 3 Wazuh components together. |
| **Cortex** | LOW | SSO via `application.conf` — stable format, but restart needed after config changes. |
| **TheHive** | LOW | SSO via `application.conf` — stable format. |

## MISP Digest Pinning

MISP does not publish version-tagged images. To update MISP:

```bash
# Pull new image
docker pull ghcr.io/misp/misp-docker/misp-core:latest
docker pull ghcr.io/misp/misp-docker/misp-modules:latest

# Get new digest
docker inspect ghcr.io/misp/misp-docker/misp-core:latest --format '{{index .RepoDigests 0}}'
docker inspect ghcr.io/misp/misp-docker/misp-modules:latest --format '{{index .RepoDigests 0}}'

# Update docker-compose.yml with new sha256 digest
# Then: docker-compose up -d socstack-misp-core socstack-misp-modules
```
