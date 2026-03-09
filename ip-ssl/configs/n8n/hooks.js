/**
 * n8n Community Edition SSO Hook (v3.2 - Shared Owner Session + Origin Fix)
 *
 * Bypasses n8n CE's workflow sharing limitation by logging ALL SSO users
 * into the single owner account. This way everyone sees the same workflows,
 * credentials, and executions.
 *
 * Flow:
 *   Browser -> NPM -> oauth2-proxy (Keycloak auth) -> n8n
 *   oauth2-proxy verifies Keycloak token and group membership
 *   This hook reads the trusted header, then issues a session cookie
 *   for the n8n OWNER account (not the SSO user's email)
 *
 * Why:
 *   n8n Community Edition does not support workflow sharing, RBAC, or
 *   team workspaces. Each user gets an isolated workspace. By mapping
 *   all SSO logins to the owner account, the entire SOC team shares
 *   one workspace with all workflows (Wazuh alerts, SOAR playbooks, etc.)
 *
 * Access control is handled at the oauth2-proxy level:
 *   - soc-admin AND soc-analyst Keycloak group members can reach n8n
 *   - soc-readonly is blocked before reaching this hook
 *   - Both groups get the same owner session (full workflow access)
 *
 * Origin header fix (v3.1):
 *   n8n 2.7+ validates the Origin header on /rest/push (SSE/WebSocket).
 *   oauth2-proxy strips the Origin header when proxying to the upstream.
 *   This hook reconstructs the Origin from X-Forwarded-Host + X-Forwarded-Proto
 *   headers that oauth2-proxy DOES set (with --reverse-proxy=true).
 *
 * v3.2 fix:
 *   n8n 2.7+ changed the User entity — the `role` column became a ManyToOne
 *   relation to a separate Role table. Using `UserRepo.find({ relations: ["role"] })`
 *   causes TypeORM to not load all scalar columns (email, password, etc.).
 *   issueCookie() needs email+password to create a valid JWT hash.
 *   Fix: use createQueryBuilder to explicitly select all needed fields,
 *   then join the role relation separately.
 *
 * Environment variables:
 *   N8N_FORWARD_AUTH_HEADER  - Header name from oauth2-proxy (default: X-Forwarded-Email)
 *   N8N_OWNER_EMAIL          - Owner account email (default: from DB, first global:owner)
 *   SSO_LOGOUT_URL           - Logout redirect (default: /oauth2/sign_out)
 */
module.exports = {
  n8n: {
    ready: [
      async function (server, config) {
        const headerName = (process.env.N8N_FORWARD_AUTH_HEADER || "X-Forwarded-Email").toLowerCase();
        const app = server.app;

        // Use Module.createRequire to resolve n8n internal dependencies
        const { createRequire } = require("module");
        const n8nRequire = createRequire("/usr/local/lib/node_modules/n8n/package.json");

        const Layer = n8nRequire("router/lib/layer");
        const { issueCookie } = require("/usr/local/lib/node_modules/n8n/dist/auth/jwt.js");

        const log = (level, msg) => {
          try { server.logger?.[level]?.(msg); } catch {}
          console.log(`[SSO] ${msg}`);
        };

        log("info", `Initializing SSO middleware (shared owner session), header: ${headerName}`);

        app.set("trust proxy", 1);

        const ignoreAuth = /^\/(assets|healthz|webhook|rest\/oauth2-credential|health|favicon|icons)/;
        const cookieName = "n8n-auth";
        const UserRepo = this.dbCollections.User;

        // ── Find the n8n owner account (once at startup) ──
        // The owner is the first user created by post-deploy.py with role global:owner
        //
        // IMPORTANT: n8n 2.7+ changed User.role from a string column to a ManyToOne
        // relation (Role entity). Using UserRepo.find({ relations: ["role"] }) causes
        // TypeORM to NOT load scalar columns like email/password. issueCookie() needs
        // these fields to create a valid JWT. We use createQueryBuilder to explicitly
        // select all user columns + join the role relation.
        let ownerUser = null;
        const ownerEmail = process.env.N8N_OWNER_EMAIL || "";

        async function findOwner() {
          if (ownerUser) return ownerUser;

          try {
            // Use queryBuilder to ensure ALL user columns are selected
            // alongside the role relation (avoids the n8n 2.7+ TypeORM issue)
            const qb = UserRepo.createQueryBuilder("user")
              .leftJoinAndSelect("user.role", "role");

            if (ownerEmail) {
              // Strategy 1: Find by env var email
              ownerUser = await qb
                .where("user.email = :email", { email: ownerEmail.toLowerCase() })
                .getOne();

              if (ownerUser) {
                log("info", `Owner found by email: ${ownerUser.email} (role: ${ownerUser.role?.slug || "?"})`);
                return ownerUser;
              }
            }

            // Strategy 2: Find user with global:owner role
            ownerUser = await UserRepo.createQueryBuilder("user")
              .leftJoinAndSelect("user.role", "role")
              .where("role.slug = :slug", { slug: "global:owner" })
              .getOne();

            if (ownerUser) {
              log("info", `Owner found by role: ${ownerUser.email} (role: ${ownerUser.role?.slug || "?"})`);
              return ownerUser;
            }

            // Strategy 3: Fallback to first user (always the owner in n8n CE)
            ownerUser = await UserRepo.createQueryBuilder("user")
              .leftJoinAndSelect("user.role", "role")
              .orderBy("user.createdAt", "ASC")
              .getOne();

            if (ownerUser) {
              log("info", `Owner fallback (first user): ${ownerUser.email} (role: ${ownerUser.role?.slug || "?"})`);
            } else {
              log("error", "No users found in database — owner lookup failed");
            }
          } catch (err) {
            log("error", `Owner lookup error: ${err.message}`);
            // Fallback: try the simple find without relations
            try {
              const users = await UserRepo.find();
              if (users.length > 0) {
                ownerUser = users[0];
                log("info", `Owner fallback (simple find): id=${ownerUser.id}, email=${ownerUser.email}`);
              }
            } catch (e2) {
              log("error", `Owner fallback also failed: ${e2.message}`);
            }
          }

          return ownerUser;
        }

        // Pre-warm the owner lookup
        await findOwner();

        // ── Middleware stack injection ──
        const { stack } = app._router || app.router;
        const idx = stack.findIndex((l) => l?.name === "cookieParser");

        if (idx === -1) {
          log("error", "cookieParser not found in middleware stack, trying fallback position");
        }

        // ── FIX: Reconstruct missing Origin header (n8n 2.7+ origin validation) ──
        // oauth2-proxy strips the Origin header when proxying to the upstream.
        // n8n's push endpoint (/rest/push) requires a valid Origin header for
        // SSE/WebSocket connections. Without this fix, push connections fail with
        // "Invalid origin!" and the editor shows "connection lost".
        //
        // We reconstruct the Origin from X-Forwarded-Host + X-Forwarded-Proto
        // that oauth2-proxy sets when --reverse-proxy=true is enabled.
        const originFixLayer = new Layer("/", { strict: false, end: false }, (req, res, next) => {
          if (!req.headers.origin) {
            const fwdHost = req.headers["x-forwarded-host"] || req.headers.host;
            const fwdProto = (req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
            if (fwdHost) {
              // Strip port from host if it's the default for the protocol
              const host = fwdHost.split(",")[0].trim();
              req.headers.origin = `${fwdProto}://${host}`;
            }
          }
          next();
        });
        originFixLayer.name = "ssoOriginFix";

        // ── SSO session middleware ──
        const ssoLayer = new Layer("/", { strict: false, end: false }, async (req, res, next) => {
          try {
            if (ignoreAuth.test(req.url)) return next();

            // Skip if already authenticated via n8n-auth cookie
            if (req.cookies?.[cookieName]) return next();

            // Read email from trusted proxy header (proves Keycloak auth passed)
            const emailHeader = req.headers[headerName];
            if (!emailHeader) return next();

            const ssoEmail = String(emailHeader).trim().toLowerCase();
            if (!ssoEmail || !ssoEmail.includes("@")) return next();

            // Find the owner account
            const owner = await findOwner();
            if (!owner) {
              log("error", `Cannot issue session — owner account not found. SSO user: ${ssoEmail}`);
              return next();
            }

            // Issue session cookie for the OWNER account (not the SSO user)
            await issueCookie(res, owner);
            log("info", `SSO login: ${ssoEmail} -> owner session (${owner.email})`);
            return next();
          } catch (error) {
            log("error", `Middleware error: ${error.message}`);
            return next();
          }
        });
        ssoLayer.name = "ssoSessionIssuer";

        // Insert both middleware after cookieParser (or at position 2 as fallback)
        // Order: ... cookieParser -> originFix -> ssoSession -> ... (rest of n8n stack)
        const insertIdx = idx !== -1 ? idx + 1 : 2;
        stack.splice(insertIdx, 0, originFixLayer, ssoLayer);
        log("info", `Origin fix middleware installed at stack position ${insertIdx}`);
        log("info", `SSO session middleware installed at stack position ${insertIdx + 1}`);

        // ── Logout: clear n8n cookie + redirect through oauth2-proxy logout ──
        const ssoLogoutUrl = process.env.SSO_LOGOUT_URL || "/oauth2/sign_out";

        // Intercept n8n's native logout (POST /rest/logout)
        // Without this, n8n only clears its own cookie but oauth2-proxy's
        // session (_n8n_oauth2 cookie) stays alive, so the user is immediately
        // auto-logged back in. We redirect through the full chain:
        //   POST /rest/logout -> 303 -> /oauth2/sign_out -> Keycloak logout -> /
        app.post("/rest/logout", (req, res) => {
          res.clearCookie(cookieName, { path: "/" });
          res.redirect(303, ssoLogoutUrl);
        });

        // SSO logout helper (GET)
        app.get("/sso-logout", (req, res) => {
          res.clearCookie(cookieName, { path: "/" });
          res.redirect(ssoLogoutUrl);
        });

        log("info", "SSO hook initialization complete (shared owner session mode)");
      }
    ]
  }
};
