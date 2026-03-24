'use strict';

/**
 * tunel — E2EE Chat Server
 *
 * Security model:
 *  ─ Pure relay: server never sees plaintext. All crypto is client-side (WebCrypto).
 *  ─ Host auth:  timing-safe token comparison against pre-hashed constant.
 *  ─ Rate limits: per-IP on HTTP and WS layers; per-message 1/s throttle.
 *  ─ WS payload: hard cap (64 KB); IV validated to exactly 12 bytes.
 *  ─ Offline blobs: stored encrypted — server cannot read content.
 *  ─ Heartbeat:   server-side WS ping/pong; dead sockets terminated in ~40 s.
 *  ─ Origin check: cross-origin WS connections rejected (localhost exempt).
 *  ─ TOFU identity: persisted Ed25519 key pair lets clients detect server swaps.
 *  ─ Session safety: VID fixation prevented; IP-per-session enforced correctly.
 *  ─ Nick broadcast: host nick_update with no 'to' field broadcasts to all visitors.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer, OPEN } = require('ws');

// ── Configuration ─────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST_TOKEN = process.env.HOST_TOKEN;
if (!HOST_TOKEN) {
  console.error('\n[CRITICAL] HOST_TOKEN is not set. Example:');
  console.error('  export HOST_TOKEN=$(openssl rand -hex 32)\n');
  process.exit(1);
}

// Pre-hash at startup so timingSafeEqual always compares equal-length buffers,
// preventing timing side-channels from mismatched buffer sizes.
const HOST_TOKEN_HASH = crypto.createHash('sha256').update(HOST_TOKEN).digest();

// ── State ─────────────────────────────────────────────────────────────────────

let hostWs = null;   // currently authenticated host socket
let hostNick = null;   // host display name (mirrored for late-joining visitors)
let hostLongtermPubkey = null;   // ECDH pubkey bytes for offline message encryption

const visitors = new Map();  // visitorId → { ws, nick, ip }
const offlineMessages = [];         // encrypted blobs only — server cannot decrypt
const MAX_OFFLINE = 200;

// ── Server Identity — Trust On First Use ──────────────────────────────────────

const ID_FILE = path.join(__dirname, '.server_identity');
let serverPubKey = '';

try {
  if (fs.existsSync(ID_FILE)) {
    serverPubKey = JSON.parse(fs.readFileSync(ID_FILE, 'utf8')).pub;
  } else {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    serverPubKey = publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
    const priv = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
    fs.writeFileSync(ID_FILE, JSON.stringify({ pub: serverPubKey, priv }), { mode: 0o600 });
    console.log('[tunel] Generated server identity (.server_identity).');
  }
} catch (e) {
  console.error('[tunel] Server identity error:', e.message);
}

// ── Rate Limiting ──────────────────────────────────────────────────────────────

const rateLimits = new Map(); // "prefix:ip" → [timestamps]
const lastMsgTime = new Map(); // ip → timestamp  (per-second chat throttle)
const MAX_RL_IPS = 5000;

function checkRate(key, max, windowMs) {
  const now = Date.now();
  let list = (rateLimits.get(key) || []).filter(t => now - t < windowMs);
  list.push(now);
  if (!rateLimits.has(key) && rateLimits.size >= MAX_RL_IPS) {
    rateLimits.delete(rateLimits.keys().next().value);
  }
  rateLimits.set(key, list);
  return list.length <= max;
}

// Cleanup stale rate-limit and throttle entries every 5 minutes
setInterval(() => {
  const cutoff = Date.now() - 120_000;
  for (const [k, ts] of rateLimits) {
    const f = ts.filter(t => t > cutoff);
    if (f.length) rateLimits.set(k, f); else rateLimits.delete(k);
  }
  for (const [ip, ts] of lastMsgTime) {
    if (ts < cutoff) lastMsgTime.delete(ip);
  }
}, 300_000).unref();

// ── Security Headers ──────────────────────────────────────────────────────────

const BASE_SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains'
};

function applyHeaders(res, nonce = null) {
  for (const [k, v] of Object.entries(BASE_SECURITY_HEADERS)) {
    res.setHeader(k, v);
  }

  // Generate dynamic CSP if a nonce is provided (for index.html)
  if (nonce) {
    const csp = [
      "default-src 'self'",
      "connect-src 'self' wss:",
      "img-src 'self' data:",
      `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
      `style-src-elem 'self' 'nonce-${nonce}'`,
      "style-src-attr 'unsafe-inline'", // Needed for app.js calculating heights dynamically
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'none'"
    ].join('; ');
    res.setHeader('Content-Security-Policy', csp);
  }
}

// ── Static File Map ───────────────────────────────────────────────────────────

const PUBLIC = path.join(__dirname, 'public');
const STATIC = {
  '/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'application/javascript; charset=utf-8' },
  '/public/app.js': { file: 'app.js', type: 'application/javascript; charset=utf-8' },
  '/style.css': { file: 'style.css', type: 'text/css; charset=utf-8' },
  '/public/style.css': { file: 'style.css', type: 'text/css; charset=utf-8' },
  '/favicon.ico': { file: 'favicon.ico', type: 'image/svg+xml' },
  '/public/favicon.ico': { file: 'favicon.ico', type: 'image/svg+xml' },
};

// ── SRI Hashes & File Caching ─────────────────────────────────────────────────

const fileCache = new Map();
let appSri = '';
let styleSri = '';

try {
  // Read files into memory for fast serving
  const appJs = fs.readFileSync(path.join(PUBLIC, 'app.js'));
  const styleCss = fs.readFileSync(path.join(PUBLIC, 'style.css'));
  const indexHtml = fs.readFileSync(path.join(PUBLIC, 'index.html'), 'utf8');
  const favicon = fs.readFileSync(path.join(PUBLIC, 'favicon.ico'));

  fileCache.set('app.js', appJs);
  fileCache.set('style.css', styleCss);
  fileCache.set('index.html', indexHtml);
  fileCache.set('favicon.ico', favicon);

  // Generate Base64 SHA-384 hashes for Subresource Integrity
  appSri = 'sha384-' + crypto.createHash('sha384').update(appJs).digest('base64');
  styleSri = 'sha384-' + crypto.createHash('sha384').update(styleCss).digest('base64');

  console.log('[tunel] SRI Hashes generated successfully.');
} catch (e) {
  console.error('[CRITICAL] Failed to load static files for SRI:', e.message);
  process.exit(1);
}

// ── HTTP Server ───────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  const forwarded = req.headers['x-forwarded-for'] || '';
  const ip = (forwarded.split(',').pop() || '').trim()
    || req.socket.remoteAddress || 'unknown';

  if (req.headers['x-forwarded-proto'] === 'http') {
    res.writeHead(301, { Location: 'https://' + req.headers.host + req.url });
    res.end();
    return;
  }

  if (!checkRate('http:' + ip, 200, 60_000)) {
    res.writeHead(429, { 'Retry-After': '60', 'Content-Type': 'text/plain' });
    res.end('Too Many Requests');
    return;
  }

  if (req.method !== 'GET') {
    res.writeHead(405, { Allow: 'GET' });
    res.end('Method Not Allowed');
    return;
  }

  // Normalize URLs
  let url = req.url === '/' ? '/index.html' : req.url;
  if (url.startsWith('/public/')) url = url.replace('/public', '');

  const entry = STATIC[url];

  if (entry) {
    if (entry.file === 'index.html') {
      // 1. Generate 16-byte random cryptographically secure nonce
      const nonce = crypto.randomBytes(16).toString('base64');

      // 2. Apply headers with the dynamic CSP
      applyHeaders(res, nonce);

      // 3. Inject Nonce and SRI into the cached HTML payload
      let html = fileCache.get('index.html')
        .replace(
          '<link rel="stylesheet" href="style.css">',
          `<link rel="stylesheet" href="style.css" nonce="${nonce}" integrity="${styleSri}" crossorigin="anonymous">`
        )
        .replace(
          '<script src="app.js"></script>',
          `<script src="app.js" nonce="${nonce}" integrity="${appSri}" crossorigin="anonymous"></script>`
        );

      // 4. Send response (must be no-store so the browser never caches an old nonce)
      res.writeHead(200, { 'Content-Type': entry.type, 'Cache-Control': 'no-store' });
      res.end(html);
    } else {
      // Serve app.js or style.css directly from RAM cache (no dynamic nonce needed here)
      applyHeaders(res);
      res.writeHead(200, { 'Content-Type': entry.type, 'Cache-Control': 'no-store' });
      res.end(fileCache.get(entry.file));
    }
    return;
  }

  applyHeaders(res);
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

// ── WebSocket Server ──────────────────────────────────────────────────────────

const wss = new WebSocketServer({
  server,
  path: '/ws',
  maxPayload: 64 * 1024,
});

// ── Server-side Heartbeat ─────────────────────────────────────────────────────

setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch { /* ignore */ }
  }
}, 30_000).unref();

// ── Helpers ───────────────────────────────────────────────────────────────────

function uid() { return crypto.randomBytes(8).toString('hex'); }
function str(v, max) { return typeof v === 'string' ? v.slice(0, max) : ''; }
function arr(v, max) { return Array.isArray(v) ? v.slice(0, max) : []; }
function safeByte(b) { return typeof b === 'number' && b >= 0 && b <= 255 ? b : 0; }

function send(ws, obj) {
  if (ws && ws.readyState === OPEN) {
    try { ws.send(JSON.stringify(obj)); } catch { /* ignore */ }
  }
}

/**
 * Sanitise an incoming chat message: allow only fields the relay may forward.
 *   - IV must be exactly 12 bytes (AES-GCM requirement).
 *   - Ciphertext capped at 6000 bytes (matches maxLength=1000 char client limit).
 * Returns null on any malformed input; caller silently drops the message.
 */
function sanitiseChat(msg) {
  if (!Array.isArray(msg.iv) || msg.iv.length !== 12) return null;
  if (!Array.isArray(msg.ciphertext) || !msg.ciphertext.length) return null;

  const out = {
    iv: msg.iv.map(safeByte),
    ciphertext: msg.ciphertext.slice(0, 6000).map(safeByte),
  };
  if (msg.nick) out.nick = str(msg.nick, 32);
  if (msg.mid) out.mid = str(msg.mid, 32);
  return out;
}

// ── WebSocket Connection Handler ──────────────────────────────────────────────

wss.on('connection', (ws, req) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  const forwarded = req.headers['x-forwarded-for'] || '';
  const ip = (forwarded.split(',').pop() || '').trim()
    || req.socket.remoteAddress || 'unknown';

  // Reject cross-origin browser connections
  const origin = req.headers.origin;
  if (origin) {
    const originHost = origin.replace(/^https?:\/\//, '').split(':')[0];
    const reqHost = (req.headers.host || '').split(':')[0];
    const isLocal = ['localhost', '127.0.0.1', '::1'].includes(originHost);
    if (!isLocal && originHost !== reqHost) {
      ws.close(1008, 'Cross-origin connections not allowed');
      return;
    }
  }

  if (!checkRate('ws:' + ip, 60, 60_000)) {
    ws.close(1008, 'Rate limit exceeded');
    return;
  }

  send(ws, { type: 'server_hello', pubkey: serverPubKey });

  let role = null;
  let visitorId = null;

  ws.on('message', raw => {
    if (!checkRate('msg:' + ip, 1000, 60_000)) {
      ws.close(1008, 'Rate limit exceeded');
      return;
    }

    let msg;
    try {
      msg = JSON.parse(raw.toString('utf8'));
    } catch {
      ws.close(1003, 'Unsupported Data');
      return;
    }

    if (typeof msg !== 'object' || msg === null || typeof msg.type !== 'string') return;

    const type = msg.type;

    // Per-second throttle for content-bearing types
    if (type === 'chat' || type === 'offline_message' || type === 'nick_update') {
      const now = Date.now(), last = lastMsgTime.get(ip) || 0;
      if (now - last < 1000) {
        send(ws, { type: 'error', message: 'Message rate limit: 1 per second' });
        return;
      }
      lastMsgTime.set(ip, now);
    }

    if (type === 'msg_ack' && !checkRate('ack:' + ip, 500, 5000)) {
      send(ws, { type: 'error', message: 'Read receipt rate limit exceeded' });
      return;
    }

    if (type === '__ping') { send(ws, { type: '__pong' }); return; }

    // ── Host Authentication ──────────────────────────────────────────────────
    if (type === 'host_auth') {
      if (role !== null) return;

      const provided = str(msg.token, 512);
      const providedHash = crypto.createHash('sha256').update(provided).digest();

      if (!crypto.timingSafeEqual(providedHash, HOST_TOKEN_HASH)) {
        send(ws, { type: 'auth_failed' });
        setTimeout(() => ws.close(1008, 'Authentication failed'), 500);
        return;
      }

      // Evict previous host session if one exists
      if (hostWs && hostWs !== ws && hostWs.readyState === OPEN) {
        send(hostWs, { type: 'error', message: 'Replaced by new session' });
        hostWs.close(1008, 'Replaced by new session');
      }

      role = 'host';
      hostWs = ws;
      hostNick = str(msg.nick, 32);

      send(ws, { type: 'auth_success', offlineMessages, visitorCount: visitors.size });

      for (const [vid, v] of visitors) {
        send(v.ws, { type: 'host_online', nick: hostNick });
        send(ws, { type: 'visitor_waiting', visitorId: vid, nick: v.nick });
      }
      return;
    }

    // ── Host: Register Long-Term Public Key ──────────────────────────────────
    if (type === 'host_set_longterm_pubkey' && role === 'host') {
      const pk = arr(msg.pubkey, 200);
      if (pk.length === 65) {  // uncompressed P-256: 0x04 + 32 + 32
        hostLongtermPubkey = pk;
        console.log('[tunel] Host long-term pubkey registered.');
      }
      return;
    }

    // ── Host: Clear Offline Messages ─────────────────────────────────────────
    if (type === 'host_clear_offline' && role === 'host') {
      offlineMessages.length = 0;
      send(ws, { type: 'offline_cleared' });
      return;
    }

    // ── Visitor Registration ─────────────────────────────────────────────────
    if (type === 'visitor_hello') {
      if (role !== null) return;

      let proposed = str(msg.vid, 16);
      if (proposed.length !== 16 || !/^[0-9a-f]{16}$/.test(proposed)) {
        proposed = uid();
      } else {
        const existing = visitors.get(proposed);
        if (existing && existing.ws !== ws && existing.ws.readyState === OPEN) {
          proposed = uid();  // VID claimed by live session — issue fresh one
        }
      }
      visitorId = proposed;

      for (const [v_vid, v] of visitors) {
        if (v.ip === ip && v_vid !== visitorId) {
          ws.close(1008, 'Only one active session per IP');
          return;
        }
      }

      role = 'visitor';
      const nick = str(msg.nick, 32);
      visitors.set(visitorId, { ws, nick, ip });
      send(ws, { type: 'visitor_welcome', vid: visitorId });

      if (hostWs && hostWs.readyState === OPEN) {
        send(ws, { type: 'host_online', nick: hostNick });
        send(hostWs, { type: 'visitor_waiting', visitorId, nick });
      } else {
        send(ws, { type: 'host_offline', hostPubkey: hostLongtermPubkey });
      }
      return;
    }

    // ── Key Exchange ─────────────────────────────────────────────────────────
    if (type === 'visitor_key' && role === 'visitor' && hostWs) {
      send(hostWs, { type: 'visitor_key', visitorId, pubkey: arr(msg.pubkey, 200) });
      return;
    }

    if (type === 'host_key' && role === 'host') {
      const target = visitors.get(str(msg.to, 20));
      if (target) send(target.ws, { type: 'host_key', pubkey: arr(msg.pubkey, 200) });
      return;
    }

    // ── Nickname Update ──────────────────────────────────────────────────────
    if (type === 'nick_update') {
      const nick = str(msg.nick, 32);
      if (role === 'host') {
        hostNick = nick;
        const toId = str(msg.to, 20);
        if (toId) {
          // Targeted: specific visitor only
          const target = visitors.get(toId);
          if (target) send(target.ws, { type: 'nick_update', nick });
        } else {
          // Broadcast: no target specified — notify ALL visitors
          for (const [, v] of visitors) send(v.ws, { type: 'nick_update', nick });
        }
      } else if (role === 'visitor') {
        const v = visitors.get(visitorId);
        if (v) v.nick = nick;
        if (hostWs) send(hostWs, { type: 'nick_update', from: visitorId, nick });
      }
      return;
    }

    // ── Read Receipts ────────────────────────────────────────────────────────
    if (type === 'msg_ack') {
      if (role === 'host') {
        const target = visitors.get(str(msg.to, 20));
        if (target) send(target.ws, { type: 'msg_ack', mid: str(msg.mid, 32) });
      } else if (role === 'visitor' && hostWs) {
        send(hostWs, { type: 'msg_ack', from: visitorId, mid: str(msg.mid, 32) });
      }
      return;
    }

    // ── Chat Relay ───────────────────────────────────────────────────────────
    if (type === 'chat') {
      const sanitised = sanitiseChat(msg);
      if (!sanitised) return;

      if (role === 'host') {
        const target = visitors.get(str(msg.to, 20));
        if (target) send(target.ws, { type: 'chat', ...sanitised });
      } else if (role === 'visitor' && hostWs) {
        send(hostWs, { type: 'chat', from: visitorId, ...sanitised });
      }
      return;
    }

    // ── Host Pubkey Request (for offline messages) ────────────────────────────
    if (type === 'request_host_pubkey') {
      send(ws, { type: 'host_pubkey', pubkey: hostLongtermPubkey });
      return;
    }

    // ── Offline Message ──────────────────────────────────────────────────────
    if (type === 'offline_message') {
      if (offlineMessages.length >= MAX_OFFLINE) {
        send(ws, { type: 'error', message: 'Offline message queue is full' });
        return;
      }
      if (!checkRate('offline:' + ip, 1, 30_000)) {
        send(ws, { type: 'error', message: 'Too many offline messages (limit: 1 per 30 s)' });
        return;
      }

      const iv = arr(msg.iv, 12);
      const sp = arr(msg.senderPubkey, 200);
      const ct = arr(msg.ciphertext, 10000);

      if (iv.length !== 12 || sp.length === 0 || ct.length === 0) {
        send(ws, { type: 'error', message: 'Malformed offline message' });
        return;
      }

      offlineMessages.push({
        id: uid(),
        ts: Date.now(),
        senderPubkey: sp.map(safeByte),
        iv: iv.map(safeByte),
        ciphertext: ct.map(safeByte),
      });

      send(ws, { type: 'offline_message_saved' });
      if (hostWs && hostWs.readyState === OPEN) {
        send(hostWs, { type: 'new_offline_message', offlineMessages });
      }
      return;
    }
  });

  ws.on('close', () => {
    if (role === 'host') {
      hostWs = null;
      hostNick = null;
      for (const [, v] of visitors) {
        send(v.ws, { type: 'host_offline', hostPubkey: hostLongtermPubkey });
      }
      console.log('[tunel] Host disconnected.');
    } else if (role === 'visitor' && visitorId) {
      // Guard: only evict if this socket is still the live registration.
      if (visitors.get(visitorId)?.ws === ws) {
        visitors.delete(visitorId);
        if (hostWs) send(hostWs, { type: 'visitor_disconnected', visitorId });
      }
    }
  });

  ws.on('error', err => {
    if (err.code !== 'ECONNRESET') console.error('[tunel] WS error:', err.message);
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`\n🔐 tunel → http://localhost:${PORT}`);
  console.log(`   Host   → http://localhost:${PORT}/#/mode/host`);
  console.log('─'.repeat(50) + '\n');
});

server.on('error', err => {
  console.error('Server error:', err.message);
  process.exit(1);
});
