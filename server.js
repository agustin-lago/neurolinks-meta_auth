import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { URL } from 'node:url';

function cleanEnv(value, fallback = '') {
  if (value === undefined || value === null) return fallback;
  let normalized = String(value).trim();
  if ((normalized.startsWith('"') && normalized.endsWith('"')) || (normalized.startsWith("'") && normalized.endsWith("'"))) {
    normalized = normalized.slice(1, -1);
  }
  return normalized || fallback;
}

function loadLocalEnv() {
  const envPath = path.join(process.cwd(), '.env');
  if (!fs.existsSync(envPath)) return;

  const content = fs.readFileSync(envPath, 'utf8');
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const separator = trimmed.indexOf('=');
    if (separator === -1) continue;

    const key = trimmed.slice(0, separator).trim();
    const value = cleanEnv(trimmed.slice(separator + 1));
    if (key && process.env[key] === undefined) process.env[key] = value;
  }
}

loadLocalEnv();

const configuredPort = Number(cleanEnv(process.env.PORT, '3000'));
const PORT = Number.isInteger(configuredPort) && configuredPort > 0 ? configuredPort : 3000;
const META_APP_ID = cleanEnv(process.env.META_APP_ID);
const META_CONFIG_ID = cleanEnv(process.env.META_CONFIG_ID);
const META_API_VERSION = cleanEnv(process.env.META_API_VERSION, 'v22.0');
const META_AUTH_SHARED_SECRET = cleanEnv(process.env.META_AUTH_SHARED_SECRET);
const ALLOWED_REDIRECT_HOSTS = cleanEnv(process.env.ALLOWED_REDIRECT_HOSTS, 'up.railway.app,clientesneurolinks.com')
  .split(',')
  .map((v) => v.trim().toLowerCase())
  .filter(Boolean);

const SECURITY_HEADERS = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
};

function json(res, status, body) {
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'content-type': 'application/json; charset=utf-8',
  });
  res.end(JSON.stringify(body));
}

function html(res, status, body) {
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'content-type': 'text/html; charset=utf-8',
    'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://connect.facebook.net; connect-src 'self' https://www.facebook.com https://web.facebook.com https://graph.facebook.com; frame-src https://www.facebook.com https://web.facebook.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'self'",
  });
  res.end(body);
}

function base64urlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

function base64urlDecode(value) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

function signPayload(payload) {
  return crypto.createHmac('sha256', META_AUTH_SHARED_SECRET).update(payload).digest('base64url');
}

function timingSafeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

function isAllowedRedirect(rawRedirectUri) {
  try {
    const url = new URL(rawRedirectUri);
    if (url.protocol !== 'https:') return false;
    return ALLOWED_REDIRECT_HOSTS.some((host) => url.hostname === host || url.hostname.endsWith(`.${host}`));
  } catch {
    return false;
  }
}

function readSignedPayload(searchParams) {
  const payload = searchParams.get('payload') || '';
  const sig = searchParams.get('sig') || '';

  if (payload.length > 4096 || sig.length > 256) {
    return { ok: false, status: 413, error: 'Signed session is too large' };
  }

  if (!META_AUTH_SHARED_SECRET) {
    return { ok: false, status: 500, error: 'META_AUTH_SHARED_SECRET is not configured' };
  }
  if (!payload || !sig) {
    return { ok: false, status: 403, error: 'Missing signed session' };
  }

  const expected = signPayload(payload);
  if (!timingSafeEqual(sig, expected)) {
    return { ok: false, status: 403, error: 'Invalid signed session' };
  }

  let data;
  try {
    data = JSON.parse(base64urlDecode(payload));
  } catch {
    return { ok: false, status: 400, error: 'Invalid payload' };
  }

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return { ok: false, status: 400, error: 'Invalid payload shape' };
  }

  const now = Math.floor(Date.now() / 1000);
  if (!data.exp || Number(data.exp) < now) {
    return { ok: false, status: 403, error: 'Expired session' };
  }

  if (!data.projectId || !data.redirectUri) {
    return { ok: false, status: 400, error: 'Missing projectId or redirectUri' };
  }

  if (!isAllowedRedirect(data.redirectUri)) {
    return { ok: false, status: 403, error: 'Redirect host is not allowed' };
  }

  return { ok: true, data };
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[char]));
}

function errorPage(title, detail) {
  const safeTitle = escapeHtml(title);
  const safeDetail = escapeHtml(detail);
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${safeTitle}</title><style>body{font-family:system-ui;margin:0;min-height:100vh;display:grid;place-items:center;background:#0f1117;color:#f8fafc}main{max-width:520px;padding:28px}p{color:#b8c0cc}</style></head><body><main><h1>${safeTitle}</h1><p>${safeDetail}</p></main></body></html>`;
}

function buildMetaAuthPage(session) {
  const appId = session.metaAppId || META_APP_ID;
  const configId = session.configId || META_CONFIG_ID;
  const projectId = session.projectId;
  const redirectUri = session.redirectUri;
  const state = session.state || session.nonce || crypto.randomUUID();

  if (!appId || !configId) {
    return { status: 500, body: errorPage('Configuracion incompleta', 'Faltan META_APP_ID o META_CONFIG_ID.') };
  }

  const safe = (value) => JSON.stringify(String(value || ''));

  return {
    status: 200,
    body: `<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Conectar con Meta | Neurolinks</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0f1117; color: #f8fafc; }
    main { width: min(92vw, 520px); border: 1px solid rgba(255,255,255,.12); border-radius: 16px; padding: 28px; background: rgba(255,255,255,.055); box-shadow: 0 20px 70px rgba(0,0,0,.35); }
    h1 { margin: 0 0 10px; font-size: 1.55rem; }
    p { color: #b8c0cc; line-height: 1.5; }
    button { width: 100%; border: 0; border-radius: 12px; padding: 14px 18px; background: #1877f2; color: white; font-weight: 800; cursor: pointer; font-size: 1rem; }
    button:disabled { opacity: .65; cursor: wait; }
    #status { min-height: 24px; margin-top: 14px; color: #9cc2ff; font-size: .95rem; }
  </style>
</head>
<body>
  <main>
    <h1>Conectar con Meta</h1>
    <p>Estas vinculando WhatsApp Business con Neurolinks. Esta pantalla solo funciona desde el boton del backoffice.</p>
    <button id="metaBtn">Conectar con Meta</button>
    <div id="status"></div>
  </main>
  <script async defer crossorigin="anonymous" src="https://connect.facebook.net/es_LA/sdk.js"></script>
  <script>
    const appId = ${safe(appId)};
    const configId = ${safe(configId)};
    const projectId = ${safe(projectId)};
    const redirectUri = ${safe(redirectUri)};
    const state = ${safe(state)};
    let wabaId = '';
    let phoneId = '';

    window.fbAsyncInit = function () {
      FB.init({ appId, autoLogAppEvents: true, xfbml: true, version: ${safe(META_API_VERSION)} });
    };

    window.addEventListener('message', function (event) {
      if (event.origin !== 'https://www.facebook.com' && event.origin !== 'https://web.facebook.com') return;
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'WA_EMBEDDED_SIGNUP' && data.event === 'FINISH' && data.data) {
          wabaId = data.data.waba_id || '';
          phoneId = data.data.phone_number_id || '';
        }
      } catch (_) {}
    });

    function finishWith(params) {
      const target = new URL(redirectUri);
      target.searchParams.set('projectId', projectId);
      target.searchParams.set('state', state);
      if (params.code) target.searchParams.set('code', params.code);
      if (wabaId) target.searchParams.set('wabaId', wabaId);
      if (phoneId) target.searchParams.set('phoneId', phoneId);
      window.location.href = target.toString();
    }

    document.getElementById('metaBtn').addEventListener('click', function () {
      const btn = this;
      const status = document.getElementById('status');
      if (!window.FB) {
        status.textContent = 'Meta SDK aun no cargo. Intenta nuevamente.';
        return;
      }
      btn.disabled = true;
      status.textContent = 'Abriendo Meta...';
      FB.login(function (response) {
        if (response && response.authResponse) {
          if (response.authResponse.setup) {
            wabaId = wabaId || response.authResponse.setup.waba_id || '';
            phoneId = phoneId || response.authResponse.setup.phone_number_id || '';
          }
          status.textContent = 'Conexion autorizada. Redirigiendo...';
          finishWith({ code: response.authResponse.code || '' });
        } else {
          btn.disabled = false;
          status.textContent = 'La autenticacion fue cancelada o fallo.';
        }
      }, {
        config_id: configId,
        response_type: 'code',
        override_default_response_type: true,
        scope: 'whatsapp_business_management,whatsapp_business_messaging,business_management',
        extras: {
          setup: {},
          featureType: 'whatsapp_business_app_onboarding',
          sessionInfoVersion: '3'
        }
      });
    });
  </script>
</body>
</html>`,
  };
}

function handleMetaAuth(req, res, url) {
  const session = readSignedPayload(url.searchParams);
  if (!session.ok) {
    html(res, session.status, errorPage('Acceso no autorizado', 'Esta pagina solo puede abrirse desde el boton Vincular con Meta del backoffice.'));
    return;
  }

  const page = buildMetaAuthPage(session.data);
  html(res, page.status, page.body);
}

function handleSignDebug(req, res, url) {
  if (process.env.NODE_ENV === 'production') {
    json(res, 404, { error: 'Not found' });
    return;
  }

  if (!META_AUTH_SHARED_SECRET) {
    json(res, 500, { error: 'META_AUTH_SHARED_SECRET is not configured' });
    return;
  }

  const redirectUri = url.searchParams.get('redirectUri') || '';
  const projectId = url.searchParams.get('projectId') || 'demo';

  if (!isAllowedRedirect(redirectUri)) {
    json(res, 403, { error: 'Redirect host is not allowed' });
    return;
  }

  const exp = Math.floor(Date.now() / 1000) + 600;
  const payload = base64urlEncode(JSON.stringify({ projectId, redirectUri, exp }));
  const sig = signPayload(payload);
  json(res, 200, { payload, sig, url: `/meta-auth?payload=${encodeURIComponent(payload)}&sig=${encodeURIComponent(sig)}` });
}

const server = http.createServer((req, res) => {
  if (req.method !== 'GET') {
    json(res, 405, { error: 'Method not allowed' });
    return;
  }

  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

  if (url.pathname === '/health') {
    json(res, 200, { ok: true, service: 'neurolinks-meta-auth' });
    return;
  }

  if (url.pathname === '/meta-auth') {
    handleMetaAuth(req, res, url);
    return;
  }

  if (url.pathname === '/debug/sign') {
    handleSignDebug(req, res, url);
    return;
  }

  json(res, 404, { error: 'Not found' });
});

server.requestTimeout = 30_000;
server.headersTimeout = 35_000;
server.keepAliveTimeout = 65_000;
server.maxHeadersCount = 64;

function shutdown(signal) {
  console.log(`${signal} received, closing neurolinks-meta-auth`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

server.listen(PORT, '0.0.0.0', () => {
  console.log(`neurolinks-meta-auth listening on 0.0.0.0:${PORT}`);
});