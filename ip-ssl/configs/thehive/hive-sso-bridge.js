/**
 * TheHive SSO Bridge v2
 * Translates Keycloak OIDC auth (via oauth2-proxy headers) into TheHive local login.
 *
 * Flow:
 *   Browser -> NPM -> oauth2-proxy-hive (Keycloak auth) -> this bridge -> TheHive
 *
 * Login:
 *   1. Reads X-Forwarded-Email from oauth2-proxy
 *   2. Looks up mapped TheHive credentials
 *   3. Calls TheHive /api/v1/login API
 *   4. Returns THEHIVE-SESSION cookie to browser
 *
 * Logout (JavaScript injection approach):
 *   1. Bridge injects a small <script> into TheHive's HTML pages
 *   2. Script intercepts fetch/XHR calls to /api/v1/logout
 *   3. Redirects browser to /sso-logout (full page navigation)
 *   4. /sso-logout: clears TheHive session -> 302 to /oauth2/sign_out
 *   5. oauth2-proxy clears _hive_oauth2 cookie -> redirects to Keycloak logout
 *   6. Keycloak clears session -> redirects back to hive.yourdomain.com (clean start)
 */

const http = require("http");
const https = require("https");
const { URL } = require("url");
const zlib = require("zlib");

const THEHIVE_URL = process.env.THEHIVE_URL || "http://socstack-thehive:9000";
const LISTEN_PORT = parseInt(process.env.BRIDGE_PORT || "4181");
const COOKIE_NAME = "THEHIVE-SESSION";

// Keycloak logout URL components
const SSO_DOMAIN = process.env.SSO_DOMAIN || "sso.yourdomain.com";
const SSO_REALM = process.env.SSO_REALM || "SOC";
const SSO_CLIENT_ID = process.env.SSO_CLIENT_ID || "soc-sso";
const HIVE_DOMAIN = process.env.HIVE_DOMAIN || "hive.yourdomain.com";

// =========================================================
// User mapping: Keycloak email -> TheHive credentials
// =========================================================
const USER_MAP = {};
try {
  const mappingJson = process.env.HIVE_USER_MAP || "{}";
  Object.assign(USER_MAP, JSON.parse(mappingJson));
} catch (e) {
  console.error("[Bridge] Failed to parse HIVE_USER_MAP:", e.message);
}

if (!USER_MAP[process.env.SSO_ADMIN_EMAIL] && process.env.SSO_ADMIN_EMAIL) {
  USER_MAP[process.env.SSO_ADMIN_EMAIL] = {
    user: process.env.HIVE_ADMIN_USER || "admin@thehive.local",
    password: process.env.HIVE_ADMIN_PASSWORD || "",
  };
}
if (!USER_MAP[process.env.SSO_ANALYST_EMAIL] && process.env.SSO_ANALYST_EMAIL) {
  USER_MAP[process.env.SSO_ANALYST_EMAIL] = {
    user: process.env.HIVE_ANALYST_USER || process.env.SSO_ANALYST_EMAIL,
    password: process.env.HIVE_ANALYST_PASSWORD || "",
  };
}
if (!USER_MAP[process.env.SSO_READONLY_EMAIL] && process.env.SSO_READONLY_EMAIL) {
  USER_MAP[process.env.SSO_READONLY_EMAIL] = {
    user: process.env.HIVE_READONLY_USER || process.env.SSO_READONLY_EMAIL,
    password: process.env.HIVE_READONLY_PASSWORD || "",
  };
}

console.log(`[Bridge] TheHive URL: ${THEHIVE_URL}`);
console.log(`[Bridge] Mapped users: ${Object.keys(USER_MAP).join(", ")}`);

// =========================================================
// Logout redirect script - injected into TheHive HTML pages
// Intercepts fetch/XHR logout calls and redirects to /sso-logout
// =========================================================
const LOGOUT_SCRIPT = `
<script data-sso-bridge="true">
(function(){
  var ssoLogoutUrl = '/sso-logout';

  // Intercept fetch() calls to /api/v1/logout
  var origFetch = window.fetch;
  window.fetch = function(input, init) {
    var url = typeof input === 'string' ? input : (input && input.url ? input.url : '');
    var method = (init && init.method) ? init.method.toUpperCase() : 'GET';
    if (method === 'POST' && url.indexOf('/api/v1/logout') !== -1) {
      console.log('[SSO Bridge] Intercepted logout, redirecting to SSO sign-out');
      window.location.href = ssoLogoutUrl;
      return new Promise(function(){}); // Never resolves, page is navigating away
    }
    return origFetch.apply(this, arguments);
  };

  // Intercept XMLHttpRequest for older code paths
  var origOpen = XMLHttpRequest.prototype.open;
  var origSend = XMLHttpRequest.prototype.send;
  var xhrLogout = new WeakMap();
  XMLHttpRequest.prototype.open = function(method, url) {
    if (method.toUpperCase() === 'POST' && url.indexOf('/api/v1/logout') !== -1) {
      xhrLogout.set(this, true);
    }
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function() {
    if (xhrLogout.get(this)) {
      console.log('[SSO Bridge] Intercepted XHR logout, redirecting to SSO sign-out');
      window.location.href = ssoLogoutUrl;
      return;
    }
    return origSend.apply(this, arguments);
  };

  console.log('[SSO Bridge] Logout interceptor installed');
})();
</script>`;

// =========================================================
// Helper functions
// =========================================================

function buildKeycloakLogoutUrl() {
  const postLogoutUri = encodeURIComponent(`https://${HIVE_DOMAIN}`);
  const kcLogout = `https://${SSO_DOMAIN}/realms/${SSO_REALM}/protocol/openid-connect/logout?client_id=${SSO_CLIENT_ID}&post_logout_redirect_uri=${postLogoutUri}`;
  return `/oauth2/sign_out?rd=${encodeURIComponent(kcLogout)}`;
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(";").forEach((c) => {
    const [name, ...rest] = c.trim().split("=");
    if (name) cookies[name.trim()] = rest.join("=");
  });
  return cookies;
}

function loginToTheHive(email) {
  return new Promise((resolve, reject) => {
    const creds = USER_MAP[email.toLowerCase()];
    if (!creds) {
      return reject(new Error(`No TheHive mapping for ${email}`));
    }

    const body = JSON.stringify({ user: creds.user, password: creds.password });
    const target = new URL("/api/v1/login", THEHIVE_URL);

    const options = {
      hostname: target.hostname,
      port: target.port,
      path: target.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    };

    const proto = target.protocol === "https:" ? https : http;
    const req = proto.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        if (res.statusCode === 200 || res.statusCode === 201) {
          const cookies = res.headers["set-cookie"] || [];
          const sessionCookie = cookies.find((c) => c.startsWith(COOKIE_NAME));
          if (sessionCookie) {
            resolve(sessionCookie);
          } else {
            reject(new Error("No session cookie in TheHive response"));
          }
        } else {
          reject(new Error(`TheHive login failed (${res.statusCode}): ${data.substring(0, 200)}`));
        }
      });
    });

    req.on("error", (err) => reject(err));
    req.write(body);
    req.end();
  });
}

function logoutFromTheHive(sessionCookie) {
  return new Promise((resolve, reject) => {
    const target = new URL("/api/v1/logout", THEHIVE_URL);
    const options = {
      hostname: target.hostname,
      port: target.port,
      path: target.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `${COOKIE_NAME}=${sessionCookie}`,
      },
    };

    const proto = target.protocol === "https:" ? https : http;
    const req = proto.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });

    req.on("error", (err) => {
      console.error(`[Bridge] Logout proxy error: ${err.message}`);
      resolve({ status: 500, body: "{}" });
    });
    req.end();
  });
}

// =========================================================
// Proxy with HTML injection support
// =========================================================
function proxyRequest(req, res, { injectScript = false } = {}) {
  const target = new URL(req.url, THEHIVE_URL);
  const headers = { ...req.headers, host: target.host };

  // Remove oauth2-proxy headers from upstream request
  delete headers["x-forwarded-email"];
  delete headers["x-forwarded-user"];
  delete headers["x-forwarded-groups"];
  delete headers["x-forwarded-preferred-username"];
  delete headers["x-forwarded-access-token"];

  // If we might inject script, request uncompressed response from TheHive
  if (injectScript) {
    delete headers["accept-encoding"];
  }

  const options = {
    hostname: target.hostname,
    port: target.port,
    path: target.pathname + target.search,
    method: req.method,
    headers: headers,
  };

  const proto = target.protocol === "https:" ? https : http;
  const proxyReq = proto.request(options, (proxyRes) => {
    const contentType = (proxyRes.headers["content-type"] || "").toLowerCase();
    const isHtml = contentType.includes("text/html");
    const encoding = (proxyRes.headers["content-encoding"] || "").toLowerCase();

    // If we should inject and response is HTML, buffer it
    if (injectScript && isHtml) {
      let chunks = [];
      proxyRes.on("data", (chunk) => chunks.push(chunk));
      proxyRes.on("end", () => {
        let body = Buffer.concat(chunks);

        // Decompress if needed
        const decompress = (buf, cb) => {
          if (encoding === "gzip") {
            zlib.gunzip(buf, cb);
          } else if (encoding === "deflate") {
            zlib.inflate(buf, cb);
          } else if (encoding === "br") {
            zlib.brotliDecompress(buf, cb);
          } else {
            cb(null, buf);
          }
        };

        decompress(body, (err, decompressed) => {
          if (err) {
            console.error("[Bridge] Decompression error, sending original:", err.message);
            const respHeaders = { ...proxyRes.headers };
            res.writeHead(proxyRes.statusCode, respHeaders);
            res.end(body);
            return;
          }

          let html = decompressed.toString("utf-8");

          // Only inject if not already present
          if (!html.includes('data-sso-bridge="true"')) {
            // Inject before </head> (preferred) or </body>
            if (html.includes("</head>")) {
              html = html.replace("</head>", LOGOUT_SCRIPT + "</head>");
            } else if (html.includes("</body>")) {
              html = html.replace("</body>", LOGOUT_SCRIPT + "</body>");
            } else {
              html += LOGOUT_SCRIPT;
            }
            console.log("[Bridge] Injected SSO logout script into HTML response");
          }

          const modified = Buffer.from(html, "utf-8");
          const respHeaders = { ...proxyRes.headers };

          // Update content-length and remove content-encoding (we decompressed)
          respHeaders["content-length"] = modified.length;
          delete respHeaders["content-encoding"];
          delete respHeaders["transfer-encoding"];

          res.writeHead(proxyRes.statusCode, respHeaders);
          res.end(modified);
        });
      });
    } else {
      // Normal passthrough proxy
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    }
  });

  proxyReq.on("error", (err) => {
    console.error(`[Bridge] Proxy error: ${err.message}`);
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end("Bad Gateway");
  });

  req.pipe(proxyReq);
}

// =========================================================
// HTTP Server
// =========================================================
const server = http.createServer(async (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const email = req.headers["x-forwarded-email"];
  const urlPath = (req.url || "/").split("?")[0];
  const accept = req.headers["accept"] || "";
  const isHtmlRequest = accept.includes("text/html");

  // =========================================================
  // 1. SSO LOGOUT: /sso-logout (full sign-out chain)
  //    JS injection redirects here instead of POST /api/v1/logout
  // =========================================================
  if (urlPath === "/sso-logout") {
    console.log(`[Bridge] SSO logout for: ${email || "unknown"}`);

    // Forward logout to TheHive to invalidate server-side session
    if (cookies[COOKIE_NAME]) {
      try {
        await logoutFromTheHive(cookies[COOKIE_NAME]);
        console.log(`[Bridge] TheHive session invalidated`);
      } catch (err) {
        console.error(`[Bridge] TheHive logout error: ${err.message}`);
      }
    }

    // Build redirect chain: /oauth2/sign_out -> Keycloak logout -> hive.yourdomain.com
    const logoutUrl = buildKeycloakLogoutUrl();
    console.log(`[Bridge] Redirecting to: ${logoutUrl}`);

    res.writeHead(302, {
      Location: logoutUrl,
      "Set-Cookie": `${COOKIE_NAME}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
      "Cache-Control": "no-cache, no-store, must-revalidate",
    });
    res.end();
    return;
  }

  // =========================================================
  // 2. EXISTING SESSION: Has TheHive cookie -> proxy (with script injection for HTML)
  // =========================================================
  if (cookies[COOKIE_NAME]) {
    return proxyRequest(req, res, { injectScript: isHtmlRequest });
  }

  // =========================================================
  // 3. AUTO-LOGIN: Has email from oauth2-proxy but no TheHive session
  // =========================================================
  if (email) {
    try {
      console.log(`[Bridge] Auto-login for: ${email}`);
      const sessionCookie = await loginToTheHive(email);
      console.log(`[Bridge] Login successful for: ${email}`);

      // Set the session cookie and redirect to the requested page
      res.writeHead(302, {
        "Set-Cookie": sessionCookie,
        Location: req.url || "/",
      });
      res.end();
      return;
    } catch (err) {
      console.error(`[Bridge] Login failed for ${email}: ${err.message}`);
    }
  }

  // =========================================================
  // 4. DEFAULT: Proxy to TheHive as-is (with injection for HTML)
  // =========================================================
  proxyRequest(req, res, { injectScript: isHtmlRequest });
});

server.listen(LISTEN_PORT, "0.0.0.0", () => {
  console.log(`[Bridge] TheHive SSO Bridge v2 running on port ${LISTEN_PORT}`);
  console.log(`[Bridge] SSO logout chain: /sso-logout -> ${buildKeycloakLogoutUrl()}`);
});
