// Siegestack scanner honeypot — decoy-lite mode.
// Mirrors log schema of safesapcrtx.org so cross-site joins work downstream.

export default async (request, context) => {
  const rawUrl = request.url;
  const pathStart = rawUrl.indexOf("/", rawUrl.indexOf("://") + 3);
  const rawPathAndQuery = pathStart === -1 ? "/" : rawUrl.slice(pathStart);
  const rawPath = rawPathAndQuery.split("?")[0];

  const url = new URL(request.url);
  const path = url.pathname.toLowerCase();

  // ── Path classification ────────────────────────────────────────────────
  // Ordered most-specific first. Each matcher returns a category tag + an
  // optional decoy response. Categories are the primary join key for
  // cross-site scanner correlation.

  const match = classify(path, rawPath);

  if (!match) {
    // Not a scanner probe — pass through to Netlify's normal handling.
    return;
  }

  // ── Log the hit ────────────────────────────────────────────────────────
  // Fire-and-forget; do NOT await. Edge functions bill on wall time, and
  // we want decoy responses fast enough to look like a real WP site.
  context.waitUntil(logHoneypotHit(request, context, match));

  // ── Serve the decoy ────────────────────────────────────────────────────
  return buildDecoyResponse(match);
};

// ──────────────────────────────────────────────────────────────────────────
// CLASSIFICATION
// ──────────────────────────────────────────────────────────────────────────

function classify(path, rawPath) {
  // WordPress surface — highest volume, most diagnostic
  if (/\/wp-includes\/wlwmanifest\.xml$/i.test(path)) {
    return { category: "wp_fingerprint", probe: "wlwmanifest", decoy: "wlwmanifest" };
  }
  if (/\/xmlrpc\.php/i.test(path)) {
    return { category: "wp_fingerprint", probe: "xmlrpc", decoy: "xmlrpc_rsd" };
  }
  if (/\/wp-login\.php/i.test(path)) {
    return { category: "wp_auth_probe", probe: "wp-login", decoy: "wp_login_page" };
  }
  if (/\/wp-admin(\/|$)/i.test(path)) {
    return { category: "wp_auth_probe", probe: "wp-admin", decoy: "wp_login_redirect" };
  }
  if (/\/wp-config\.php/i.test(path)) {
    return { category: "wp_leak_probe", probe: "wp-config", decoy: "empty_200" };
  }
  if (/\/wp-json(\/|$)/i.test(path)) {
    return { category: "wp_api_probe", probe: "wp-json", decoy: "wp_json_root" };
  }
  if (/\/wp-content\/(uploads|plugins|themes)/i.test(path)) {
    return { category: "wp_content_probe", probe: "wp-content", decoy: "empty_404_wp" };
  }

  // Environment / config file leaks
  if (/\/\.env(\.|$|\/)/i.test(path)) {
    return { category: "env_leak_probe", probe: "dotenv", decoy: "fake_env" };
  }
  if (/\/\.git\/(config|HEAD|index)/i.test(path)) {
    return { category: "vcs_leak_probe", probe: "git", decoy: "fake_git_config" };
  }
  if (/\/\.(svn|hg|bzr)\//i.test(path)) {
    return { category: "vcs_leak_probe", probe: "other_vcs", decoy: "empty_404" };
  }
  if (/\/\.ds_store$/i.test(path) || /\/thumbs\.db$/i.test(path)) {
    return { category: "os_artifact_probe", probe: "os_metadata", decoy: "empty_404" };
  }

  // Config / credential files
  if (/\/(config|configuration|settings|credentials|secrets)\.(php|json|yml|yaml|ini|xml|bak|old|txt)$/i.test(path)) {
    return { category: "config_leak_probe", probe: "config_file", decoy: "empty_404" };
  }
  if (/\/(database|db)\.(sql|bak|dump|backup)$/i.test(path)) {
    return { category: "config_leak_probe", probe: "db_dump", decoy: "empty_404" };
  }

  // phpMyAdmin / DB admin
  if (/\/(phpmyadmin|pma|myadmin|mysql|dbadmin|adminer)(\/|$)/i.test(path)) {
    return { category: "db_admin_probe", probe: "phpmyadmin_family", decoy: "fake_pma" };
  }

  // Generic PHP probes (common backdoor / shell names)
  if (/\/(shell|cmd|backdoor|webshell|c99|r57|wso|b374k|filesman|hacked|eval|exec)\.php$/i.test(path)) {
    return { category: "shell_probe", probe: "webshell", decoy: "empty_404" };
  }
  if (/\/(upload|uploader|upl|fileupload)\.(php|asp|aspx|jsp)$/i.test(path)) {
    return { category: "shell_probe", probe: "upload_handler", decoy: "empty_404" };
  }

  // Framework fingerprints
  if (/\/(storage\/logs|storage\/framework|_ignition)/i.test(path)) {
    return { category: "framework_probe", probe: "laravel", decoy: "empty_404" };
  }
  if (/\/(app_dev\.php|_profiler|_wdt)/i.test(path)) {
    return { category: "framework_probe", probe: "symfony", decoy: "empty_404" };
  }
  if (/\/(administrator\/index\.php|components\/com_)/i.test(path)) {
    return { category: "framework_probe", probe: "joomla", decoy: "empty_404" };
  }
  if (/\/(user\/login|\?q=user|sites\/default\/files)/i.test(path)) {
    return { category: "framework_probe", probe: "drupal", decoy: "empty_404" };
  }

  // Cloud metadata / SSRF probes (weird at edge but some scanners try)
  if (/\/latest\/meta-data/i.test(path) || /\/metadata\/instance/i.test(path) || /\/computemetadata/i.test(path)) {
    return { category: "ssrf_probe", probe: "cloud_metadata", decoy: "empty_404" };
  }

  // Server status / info
  if (/\/(server-status|server-info|status|health|phpinfo\.php|info\.php|test\.php)$/i.test(path)) {
    return { category: "info_probe", probe: "status_page", decoy: "empty_404" };
  }

  // Common admin / setup panels
  if (/\/(admin|login|administrator|signin|wp-setup|install|setup)(\/|\.php$|$)/i.test(path)) {
    // Only match if not already handled above
    return { category: "admin_probe", probe: "generic_admin", decoy: "empty_404" };
  }

  // Backup / archive extension catchall
  if (/\.(bak|old|backup|swp|save|orig|~|tar\.gz|tgz|zip|rar|7z|sql)$/i.test(path)) {
    return { category: "backup_probe", probe: "backup_extension", decoy: "empty_404" };
  }

  // Double-slash paths (scanner script sloppy joins) that didn't match above
  // are still worth logging as they're a strong scanner tell.
  // Check rawPath (pre-URL-normalization) since new URL() collapses `//`.
  if (rawPath.includes("//")) {
    return { category: "scanner_artifact", probe: "double_slash", decoy: "empty_404" };
  }

  return null;
}

// ──────────────────────────────────────────────────────────────────────────
// DECOY RESPONSES
// ──────────────────────────────────────────────────────────────────────────

function buildDecoyResponse(match) {
  const headers = {
    "Content-Type": "text/html; charset=UTF-8",
    "X-Powered-By": "PHP/7.4.33",
    "Server": "Apache/2.4.54",
  };

  switch (match.decoy) {
    case "wlwmanifest":
      return new Response(WLW_MANIFEST, {
        status: 200,
        headers: { ...headers, "Content-Type": "text/xml; charset=UTF-8" },
      });

    case "xmlrpc_rsd":
      return new Response(XMLRPC_RSD, {
        status: 200,
        headers: { ...headers, "Content-Type": "text/xml; charset=UTF-8" },
      });

    case "wp_login_page":
      return new Response(WP_LOGIN_HTML, { status: 200, headers });

    case "wp_login_redirect":
      return new Response("", {
        status: 302,
        headers: { ...headers, "Location": "/wp-login.php" },
      });

    case "wp_json_root":
      return new Response(WP_JSON_ROOT, {
        status: 200,
        headers: { ...headers, "Content-Type": "application/json; charset=UTF-8" },
      });

    case "fake_env":
      // Fake .env — looks legit enough to trigger "harvested credentials" behavior
      // which is itself a useful signal (scanner will come back / try auth)
      return new Response(FAKE_ENV, {
        status: 200,
        headers: { ...headers, "Content-Type": "text/plain; charset=UTF-8" },
      });

    case "fake_git_config":
      return new Response(FAKE_GIT_CONFIG, {
        status: 200,
        headers: { ...headers, "Content-Type": "text/plain; charset=UTF-8" },
      });

    case "fake_pma":
      return new Response(FAKE_PMA_HTML, { status: 200, headers });

    case "empty_200":
      return new Response("", { status: 200, headers });

    case "empty_404_wp":
      // 404 but with WP-flavored body so scanners still fingerprint as WP
      return new Response(WP_404_HTML, { status: 404, headers });

    case "empty_404":
    default:
      return new Response(GENERIC_404, { status: 404, headers });
  }
}

// ──────────────────────────────────────────────────────────────────────────
// LOGGING — schema must match safesapcrtx firewall.js
// ──────────────────────────────────────────────────────────────────────────

function logHoneypotHit(request, context, match) {
  const url = new URL(request.url);
  const headers = request.headers;

  const entry = {
    site: "siegestack.com",
    ts: new Date().toISOString(),
    ip: context.ip || headers.get("x-nf-client-connection-ip") || headers.get("x-forwarded-for") || "unknown",
    geo_country: context.geo?.country?.code || null,
    geo_city: context.geo?.city || null,
    method: request.method,
    path: url.pathname,
    query: url.search || null,
    ua: headers.get("user-agent") || null,
    referer: headers.get("referer") || null,
    // TLS fingerprint: Netlify doesn't expose JA3/JA4 directly; closest
    // proxy is the Accept-* header fingerprint + UA. Real TLS fp requires
    // upstream Cloudflare or a custom log stream from your edge.
    accept: headers.get("accept") || null,
    accept_lang: headers.get("accept-language") || null,
    accept_enc: headers.get("accept-encoding") || null,
    // Scanner classification
    category: match.category,
    probe: match.probe,
    decoy_served: match.decoy,
  };

  // Emit to Netlify function logs (picked up by your existing aggregator).
  // console.log is what the safesapcrtx function uses too — single-line JSON
  // so downstream parsing is trivial.
  console.log(JSON.stringify(entry));
  return Promise.resolve();
}

// ──────────────────────────────────────────────────────────────────────────
// STATIC DECOY BODIES
// ──────────────────────────────────────────────────────────────────────────

const WLW_MANIFEST = `<?xml version="1.0" encoding="UTF-8"?>
<manifest xmlns="http://schemas.microsoft.com/wlw/manifest/weblog">
<options>
<clientType>WordPress</clientType>
<supportsKeywords>Yes</supportsKeywords>
<supportsFileUpload>Yes</supportsFileUpload>
</options>
</manifest>`;

const XMLRPC_RSD = `<?xml version="1.0" encoding="UTF-8"?>
<rsd version="1.0" xmlns="http://archipelago.phrasewise.com/rsd">
<service>
<engineName>WordPress</engineName>
<engineLink>https://wordpress.org/</engineLink>
<homePageLink>https://siegestack.com</homePageLink>
<apis>
<api name="WordPress" blogID="1" preferred="true" apiLink="https://siegestack.com/xmlrpc.php" />
</apis>
</service>
</rsd>`;

const WP_LOGIN_HTML = `<!DOCTYPE html>
<html><head><title>Log In &lsaquo; SiegeStack &mdash; WordPress</title>
<meta name="generator" content="WordPress 6.4.2" />
</head><body class="login wp-core-ui">
<div id="login"><h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<form name="loginform" id="loginform" method="post">
<p><label>Username or Email</label><input type="text" name="log" /></p>
<p><label>Password</label><input type="password" name="pwd" /></p>
<p class="submit"><input type="submit" name="wp-submit" value="Log In" /></p>
</form></div></body></html>`;

const WP_JSON_ROOT = JSON.stringify({
  name: "SiegeStack",
  description: "",
  url: "https://siegestack.com",
  home: "https://siegestack.com",
  gmt_offset: "0",
  timezone_string: "",
  namespaces: ["oembed/1.0", "wp/v2", "wp-site-health/v1"],
  authentication: [],
  _links: { help: [{ href: "https://developer.wordpress.org/rest-api/" }] },
});

const WP_404_HTML = `<!DOCTYPE html>
<html><head><title>Page not found - SiegeStack</title>
<meta name="generator" content="WordPress 6.4.2" />
</head><body class="error404">
<h1>Oops! That page can&rsquo;t be found.</h1>
</body></html>`;

const GENERIC_404 = `<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.54 Server</address></body></html>`;

// Fake .env — obviously not real credentials, but shaped like a real file.
// Scanners that parse .env files will log these as "hits" and may come back
// to try them, which is itself signal. Values are deliberately syntactically
// valid but functionally useless, and NOT the AWS docs example keys (those
// are on every honeypot-detection blocklist).
const FAKE_ENV = `APP_NAME=SiegeStack
APP_ENV=production
APP_DEBUG=false
APP_URL=https://siegestack.com

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=siegestack_prod
DB_USERNAME=ss_app
DB_PASSWORD=honeypot_not_a_real_password_3f7a1b9c

MAIL_MAILER=smtp
MAIL_HOST=smtp.example.com
MAIL_PORT=587

AWS_ACCESS_KEY_ID=AKIA4R7TQ2WMXK9LB3FN
AWS_SECRET_ACCESS_KEY=h8Kp2xQvN4mRs7tY9uZ3wL6bJ1aG5dF0cE2iH8rT
AWS_DEFAULT_REGION=us-east-1
`;

const FAKE_GIT_CONFIG = `[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[remote "origin"]
    url = git@github.com:example/siegestack.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
`;

const FAKE_PMA_HTML = `<!DOCTYPE html>
<html><head><title>phpMyAdmin</title></head>
<body><div id="page_content">
<form method="post" action="index.php">
<label>Username:</label><input type="text" name="pma_username" />
<label>Password:</label><input type="password" name="pma_password" />
<input type="submit" value="Go" />
</form>
<p>phpMyAdmin 5.2.1</p>
</div></body></html>`;

// ──────────────────────────────────────────────────────────────────────────
// Netlify edge function config
// ──────────────────────────────────────────────────────────────────────────

export const config = {
  // Match everything — classifier decides what's a probe vs pass-through.
  // Excluded paths are static assets that can't be scanner probes.
  path: "/*",
  excludedPath: [
    "/*.css", "/*.js", "/*.mjs", "/*.map",
    "/*.png", "/*.jpg", "/*.jpeg", "/*.gif", "/*.svg", "/*.webp", "/*.ico",
    "/*.woff", "/*.woff2", "/*.ttf", "/*.eot",
    "/*.mp4", "/*.webm", "/*.mp3",
    "/robots.txt", "/sitemap.xml",
    "/.netlify/*",
  ],
};
