'use strict';

/**
 * tunel — client-side application
 *
 * Crypto summary:
 *  ─ Key agreement : ECDH P-256 (ephemeral per-session → forward secrecy)
 *  ─ KDF           : HKDF-SHA-512, info='tunel-chat-v2'
 *  ─ Session cipher: AES-256-GCM, fresh random 12-byte IV per message
 *  ─ Fingerprint   : SHA-512 of ECDH shared secret, first 12 bytes (96-bit)
 *  ─ Vault KDF     : PBKDF2-SHA-512, 600 000 iterations, 32-byte salt  [v2]
 *                    (v1 vaults — SHA-256/100 k/16-byte — auto-upgrade on unlock)
 *  ─ Replay guard  : monotonic counter inside each encrypted payload
 */

/* ── Audio ─────────────────────────────────────────────────────────────────── */

let audioCtx = null;
function getAudio() {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === 'suspended') audioCtx.resume();
    return audioCtx;
}
function playTone(freqs, vol = 0.13) {
    try {
        const ctx = getAudio();
        freqs.forEach(({ f, t: start = 0, d = 0.3, type = 'sine' }) => {
            const osc = ctx.createOscillator(), g = ctx.createGain();
            osc.connect(g); g.connect(ctx.destination);
            osc.type = type; osc.frequency.value = f;
            const t0 = ctx.currentTime + start;
            g.gain.setValueAtTime(0, t0);
            g.gain.linearRampToValueAtTime(vol, t0 + 0.015);
            g.gain.exponentialRampToValueAtTime(0.0001, t0 + d);
            osc.start(t0); osc.stop(t0 + d + 0.01);
        });
    } catch { /* AudioContext unavailable */ }
}
const sounds = {
    incomingMessage: () => playTone([{ f: 1318, d: 0.1 }, { f: 880, t: 0.08, d: 0.22 }]),
    error: () => playTone([{ f: 220, d: 0.18 }, { f: 196, t: 0.14, d: 0.28 }], 0.09),
    success: () => playTone([
        { f: 523, d: 0.13 }, { f: 659, t: 0.11, d: 0.13 },
        { f: 784, t: 0.22, d: 0.18 }, { f: 1046, t: 0.33, d: 0.38 },
    ], 0.08),
};

/* ── Crypto ─────────────────────────────────────────────────────────────────── */

const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };
const HKDF_HASH = 'SHA-512';
const HKDF_INFO = new TextEncoder().encode('tunel-chat-v2');
const PBKDF2_HASH = 'SHA-512';
const PBKDF2_ITERS = 600_000;   // OWASP 2024 minimum for SHA-512 is 210 k; we use 3×
const PBKDF2_SALT_BYTES = 32;        // 256-bit salt
const FP_BYTES = 12;        // 96-bit fingerprint (12 colon-separated hex bytes)

async function genKeyPair() { return crypto.subtle.generateKey(ECDH_PARAMS, false, ['deriveKey', 'deriveBits']); }
async function genLTPair() { return crypto.subtle.generateKey(ECDH_PARAMS, true, ['deriveKey', 'deriveBits']); }
async function exportPub(kp) { return Array.from(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))); }
async function importPub(raw) { return crypto.subtle.importKey('raw', new Uint8Array(raw), ECDH_PARAMS, false, []); }

/**
 * Derive a session AES-256-GCM key + display fingerprint from an ECDH exchange.
 * Fingerprint = SHA-512 of the raw shared secret (first FP_BYTES hex pairs).
 * Session key = HKDF-SHA-512 of the raw shared secret.
 */
async function deriveSessionKey(myPriv, theirPub) {
    const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: theirPub }, myPriv, 256);

    const fpHash = await crypto.subtle.digest('SHA-512', bits);
    const fp = Array.from(new Uint8Array(fpHash).slice(0, FP_BYTES))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(':');

    const base = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: HKDF_HASH, salt: new Uint8Array(32), info: HKDF_INFO },
        base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    return { key, fp };
}

/** Encrypt plaintext `t` with monotonic counter `n` for replay detection. */
async function encMsg(key, t, n) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = JSON.stringify({ t, n, ts: Date.now() });
    const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, key, new TextEncoder().encode(payload)
    );
    return { iv: Array.from(iv), ciphertext: Array.from(new Uint8Array(ct)) };
}

/** Decrypt and parse an encrypted payload. Throws on tamper/wrong key. */
async function decMsg(key, iv, ciphertext) {
    const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(iv) }, key, new Uint8Array(ciphertext)
    );
    return JSON.parse(new TextDecoder().decode(plain));
}

/** 16-char cryptographically random hex string (128-bit message ID). */
function uid() {
    return Array.from(crypto.getRandomValues(new Uint8Array(8)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Vault KDF ─────────────────────────────────────────────────────────────────

async function deriveVaultKey(password, salt,
    hash = PBKDF2_HASH, iterations = PBKDF2_ITERS) {
    const base = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations, hash },
        base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
}

/**
 * Load and decrypt the host vault from localStorage.
 *
 * Vault v2: PBKDF2 params stored in 'tunel_vault_meta' (unencrypted) for
 *   future backward compatibility.
 * Vault v1 (legacy): SHA-256 / 100 k / 16-byte salt, salt in 'tunel_vault_salt'.
 *   Auto-upgraded to v2 on successful unlock (transparent to the user).
 */
async function loadVault(password) {
    const raw = localStorage.getItem('tunel_vault');
    if (!raw) return null;

    let salt, hash, iterations, isLegacy = false;
    const metaRaw = localStorage.getItem('tunel_vault_meta');
    if (metaRaw) {
        const meta = JSON.parse(metaRaw);
        salt = new Uint8Array(meta.salt);
        hash = meta.pbkdf2?.hash || PBKDF2_HASH;
        iterations = meta.pbkdf2?.iterations || PBKDF2_ITERS;
    } else {
        const saltRaw = localStorage.getItem('tunel_vault_salt');
        if (!saltRaw) throw new Error('Vault metadata missing — please reset the vault.');
        salt = new Uint8Array(JSON.parse(saltRaw));
        hash = 'SHA-256';
        iterations = 100_000;
        isLegacy = true;
    }

    let data;
    try {
        const passKey = await deriveVaultKey(password, salt, hash, iterations);
        const { iv, ct } = JSON.parse(raw);
        const plainBuf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: new Uint8Array(iv) }, passKey, new Uint8Array(ct)
        );
        data = JSON.parse(new TextDecoder().decode(plainBuf));
    } catch {
        throw new Error('Incorrect master password');
    }

    // Transparent v1 → v2 upgrade
    if (isLegacy) {
        try {
            await _writeVault(password, data);
            localStorage.removeItem('tunel_vault_salt');
            console.info('[tunel] Vault upgraded to v2 (PBKDF2-SHA-512 / 600 k).');
        } catch (e) {
            console.warn('[tunel] Vault upgrade skipped:', e.message);
        }
    }

    const priv = await crypto.subtle.importKey(
        'jwk', data.ltPrivJWK, ECDH_PARAMS, false, ['deriveKey', 'deriveBits']
    );
    const pub = await crypto.subtle.importKey(
        'jwk', data.ltPubJWK, ECDH_PARAMS, true, []
    );
    const rawPub = await crypto.subtle.exportKey('raw', pub);
    return {
        token: data.token,
        nick: data.nick,
        ltKeyPair: { privateKey: priv, publicKey: pub },
        pubBytes: Array.from(new Uint8Array(rawPub)),
    };
}

async function _writeVault(password, data) {
    const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_BYTES));
    const passKey = await deriveVaultKey(password, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, passKey,
        new TextEncoder().encode(JSON.stringify(data))
    );
    localStorage.setItem('tunel_vault', JSON.stringify({
        iv: Array.from(iv), ct: Array.from(new Uint8Array(ct))
    }));
    localStorage.setItem('tunel_vault_meta', JSON.stringify({
        v: 2, pbkdf2: { hash: PBKDF2_HASH, iterations: PBKDF2_ITERS },
        salt: Array.from(salt),
    }));
}

async function saveVault(password, token, nick, ltKeyPair) {
    await _writeVault(password, {
        v: 2, token, nick,
        ltPrivJWK: await crypto.subtle.exportKey('jwk', ltKeyPair.privateKey),
        ltPubJWK: await crypto.subtle.exportKey('jwk', ltKeyPair.publicKey),
    });
    S.vaultExists = true;
}

// ── Offline Crypto ────────────────────────────────────────────────────────────

async function encryptOffline(hostPubArr, obj) {
    const ep = await genKeyPair(), hp = await importPub(hostPubArr);
    const { key } = await deriveSessionKey(ep.privateKey, hp);
    const senderPub = await exportPub(ep);
    const { iv, ciphertext } = await encMsg(key, obj, 1);
    return { senderPubkey: senderPub, iv, ciphertext };
}

async function decryptOffline(ltPriv, senderPubArr, iv, ct) {
    const sp = await importPub(senderPubArr);
    const { key } = await deriveSessionKey(ltPriv, sp);
    const msg = await decMsg(key, iv, ct);
    return typeof msg.t === 'object' ? msg.t : JSON.parse(msg.t);
}

/* ── Nickname Helpers ────────────────────────────────────────────────────────── */

const LS_NICK_GUEST = 'tunel_nick_guest';
const LS_NICK_HOST = 'tunel_nick_host';

function getNickname(isHost) {
    return localStorage.getItem(isHost ? LS_NICK_HOST : LS_NICK_GUEST) || '';
}

/**
 * Persist a nickname and, only when a session is fully active, broadcast
 * the change to the peer(s).
 *
 * For the host: broadcasts to ALL connected visitors (no 'to' field → server
 * broadcasts). For a visitor: broadcasts to the host.
 */
function saveNickname(isHost, nick) {
    const lsKey = isHost ? LS_NICK_HOST : LS_NICK_GUEST;
    if (nick) localStorage.setItem(lsKey, nick); else localStorage.removeItem(lsKey);

    const active = isHost
        ? (ws2 && ws2.readyState === 1 && S._sessionActive)
        : (ws2 && ws2.readyState === 1 && S.chatReady);
    if (!active) return;

    // Host: omit 'to' so server broadcasts to all visitors
    wsSend({ type: 'nick_update', nick, ...(isHost ? {} : {}) });
}

/* ── Application State ───────────────────────────────────────────────────────── */

const S = {
    ws: null,
    isHost: location.hash.includes('/mode/host'),

    // Visitor
    kp: null,
    sessionKey: null,
    fp: null,
    sc: 0,
    rc: -1,

    // Host
    ltKey: null,
    _hostToken: null,
    ltPass: null,
    vaultExists: !!localStorage.getItem('tunel_vault'),
    _sessionActive: false,  // true only while host is authenticated
    _authToastShown: false,

    // Visitor identity
    vid: null,

    // Host multi-visitor
    sessions: new Map(),
    activeVid: null,
    unread: new Map(),

    // Shared
    _hostPub: null,
    _pendingSend: null,
    _peerNick: null,
    chatReady: false,
};

const LS_VID = 'tunel_vid';
function getVid() {
    let id = localStorage.getItem(LS_VID);
    if (!id || id.length !== 16 || !/^[0-9a-f]{16}$/.test(id)) {
        id = Array.from(crypto.getRandomValues(new Uint8Array(8)))
            .map(b => b.toString(16).padStart(2, '0')).join('');
        localStorage.setItem(LS_VID, id);
    }
    return id;
}
S.vid = getVid();

/* ── DOM Helpers ─────────────────────────────────────────────────────────────── */

const $ = id => document.getElementById(id);
const VIEWS = ['connecting', 'chat', 'offline', 'host-login', 'host-dash', 'setup'];
function showView(n) { VIEWS.forEach(v => { const el = $('view-' + v); if (el) el.hidden = v !== n; }); }

function setBadge(text, cls) {
    const b = $('win-conn-badge');
    b.textContent = text; b.className = cls || '';
}

function setEnc(fp) {
    $('enc-dot').classList.add('active');
    $('enc-label').textContent = 'AES-256-GCM · E2E';
    const el = $('fingerprint-display');
    el.textContent = fp ? 'FP ' + fp : '';
    el.title = fp ? 'Click to copy fingerprint' : '';
    el.style.cursor = fp ? 'pointer' : '';
    el.onclick = fp ? () => {
        navigator.clipboard?.writeText(fp).then(() => {
            el.textContent = '✓ copied';
            el.classList.add('fp-copied');
            setTimeout(() => { el.textContent = 'FP ' + fp; el.classList.remove('fp-copied'); }, 1800);
        }).catch(() => { });
    } : null;
}

function clrEnc() {
    $('enc-dot').classList.remove('active');
    $('enc-label').textContent = 'Not encrypted';
    const el = $('fingerprint-display');
    el.textContent = ''; el.onclick = null; el.style.cursor = '';
}

function toast(msg, dur = 3100) {
    const el = document.createElement('div');
    el.className = 'toast'; el.textContent = msg;
    $('toast-container').appendChild(el);
    setTimeout(() => el.remove(), dur);
}

/** Append a chat message bubble. Text is always set via textContent — never innerHTML. */
function addMsg(box, text, own, ts, nick, mid) {
    const w = document.createElement('div');
    w.className = 'msg ' + (own ? 'own' : 'them');
    if (mid) w.dataset.mid = mid;

    const b = document.createElement('div');
    b.className = 'msg-body'; b.textContent = text;

    const meta = document.createElement('div'); meta.className = 'msg-meta';
    if (nick) {
        const n = document.createElement('span'); n.className = 'msg-nick'; n.textContent = nick;
        meta.appendChild(n);
    }
    const t = document.createElement('span'); t.className = 'msg-time';
    t.textContent = new Date(ts || Date.now())
        .toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    meta.appendChild(t);

    if (own) {
        const ack = document.createElement('span'); ack.className = 'msg-status'; ack.textContent = '✓';
        meta.appendChild(ack);
    }

    w.appendChild(b); w.appendChild(meta);
    box.appendChild(w); box.scrollTop = box.scrollHeight;
}

function markRead(box, mid) {
    if (!mid) return;
    const el = box.querySelector(`[data-mid="${CSS.escape(mid)}"] .msg-status`);
    if (el) { el.textContent = '✓✓'; el.classList.add('read'); }
}

function addSys(box, text, cls) {
    const el = document.createElement('div');
    el.className = 'msg-system' + (cls ? ' ' + cls : '');
    el.textContent = text; box.appendChild(el); box.scrollTop = box.scrollHeight;
}

/* ── Connect Step Indicator ──────────────────────────────────────────────────── */

const STEPS = ['cstep-ws', 'cstep-key', 'cstep-exchange'];

function stepSet(id, state) {
    // state: 'active' | 'done' | ''
    const el = $(id); if (!el) return;
    el.className = state ? 'step-' + state : '';
}

function stepsReset() { STEPS.forEach(id => stepSet(id, '')); }

function stepDone(id) {
    stepSet(id, 'done');
    // activate the next step
    const idx = STEPS.indexOf(id);
    if (idx >= 0 && idx + 1 < STEPS.length) stepSet(STEPS[idx + 1], 'active');
}

/* ── Window Management ───────────────────────────────────────────────────────── */

const win = $('app-window');
const tbBtn = $('taskbar-app');
let maxed = false, savedGeom = null;

function winHide() { win.classList.add('win-hidden'); tbBtn.classList.remove('win-active'); }
function winShow() { win.classList.remove('win-hidden', 'win-minimized'); tbBtn.classList.add('win-active'); }
function winMinimize() { win.classList.add('win-minimized'); tbBtn.classList.remove('win-active'); }

tbBtn.addEventListener('click', () => {
    if (win.classList.contains('win-hidden') || win.classList.contains('win-minimized')) winShow();
    else winMinimize();
});
// Keyboard: Enter or Space activates the taskbar button
tbBtn.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); tbBtn.click(); }
});

win.querySelector('.wc-close').addEventListener('click', winHide);
win.querySelector('.wc-min').addEventListener('click', winMinimize);
win.querySelector('.wc-max').addEventListener('click', toggleMax);
$('title-bar').addEventListener('dblclick', e => { if (!e.target.closest('.win-ctrl-group')) toggleMax(); });

function toggleMax() {
    if (maxed) { maxed = false; win.classList.remove('maximized'); if (savedGeom) win.style.cssText = savedGeom; }
    else { maxed = true; savedGeom = win.style.cssText; win.classList.add('maximized'); }
}

let drag = false, dox = 0, doy = 0;
$('title-bar').addEventListener('mousedown', e => {
    if (maxed || e.target.closest('.win-ctrl-group, #nick-btn, .nick-popover')) return;
    drag = true; dox = e.clientX - win.offsetLeft; doy = e.clientY - win.offsetTop;
    e.preventDefault();
});
document.addEventListener('mousemove', e => {
    if (!drag) return;
    win.style.left = Math.max(0, Math.min(window.innerWidth - win.offsetWidth, e.clientX - dox)) + 'px';
    win.style.top = Math.max(0, Math.min(window.innerHeight - win.offsetHeight - 36, e.clientY - doy)) + 'px';
    win.style.transform = 'none';
});
document.addEventListener('mouseup', () => { drag = false; });

$('title-bar').addEventListener('touchstart', e => {
    if (maxed || e.target.closest('.win-ctrl-group, #nick-btn, .nick-popover')) return;
    const t = e.touches[0]; drag = true;
    dox = t.clientX - win.offsetLeft; doy = t.clientY - win.offsetTop;
    win.style.transform = 'none';
}, { passive: true });
document.addEventListener('touchmove', e => {
    if (!drag) return; const t = e.touches[0];
    win.style.left = Math.max(0, t.clientX - dox) + 'px';
    win.style.top = Math.max(0, Math.min(window.innerHeight - win.offsetHeight - 36, t.clientY - doy)) + 'px';
}, { passive: true });
document.addEventListener('touchend', () => { drag = false; });

['n', 'ne', 'e', 'se', 's', 'sw', 'w', 'nw'].forEach(dir => {
    const rh = document.createElement('div'); rh.className = 'rh rh-' + dir; win.appendChild(rh);
    rh.addEventListener('mousedown', e => {
        if (maxed) return; e.preventDefault(); e.stopPropagation();
        const sx = e.clientX, sy = e.clientY,
            sw = win.offsetWidth, sh = win.offsetHeight,
            sl = win.offsetLeft, st = win.offsetTop,
            minW = 420, minH = 480;
        const mv = e => {
            const dx = e.clientX - sx, dy = e.clientY - sy;
            if (dir.includes('e')) win.style.width = Math.max(minW, sw + dx) + 'px';
            if (dir.includes('s')) win.style.height = Math.max(minH, sh + dy) + 'px';
            if (dir.includes('w')) { const nw = Math.max(minW, sw - dx); win.style.width = nw + 'px'; win.style.left = (sl + sw - nw) + 'px'; win.style.transform = 'none'; }
            if (dir.includes('n')) { const nh = Math.max(minH, sh - dy); win.style.height = nh + 'px'; win.style.top = Math.max(0, st + sh - nh) + 'px'; }
        };
        const up = () => { document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up); };
        document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
    });
});

function tick() {
    $('taskbar-clock').textContent =
        new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
tick(); setInterval(tick, 1000);

function centerWin() {
    win.style.left = Math.max(0, (window.innerWidth - win.offsetWidth) / 2) + 'px';
    win.style.top = Math.max(0, (window.innerHeight - win.offsetHeight - 36) / 2) + 'px';
    win.style.opacity = '1';
}

tbBtn.classList.add('win-active');
$('clear-offline-btn').addEventListener('mouseover', function () { this.style.color = 'var(--red)'; });
$('clear-offline-btn').addEventListener('mouseout', function () { this.style.color = ''; });

/* ── Mobile: handle virtual keyboard resize ──────────────────────────────────── */

function syncMobileHeight() {
    if (window.innerWidth < 768) {
        const vvh = window.visualViewport ? window.visualViewport.height : window.innerHeight;
        win.style.height = vvh + 'px';
        win.style.top = (window.visualViewport ? window.visualViewport.offsetTop : 0) + 'px';
        const box = S.isHost ? $('messages-host') : $('messages');
        if (box) box.scrollTop = box.scrollHeight;
    }
}
if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', syncMobileHeight);
    window.visualViewport.addEventListener('scroll', syncMobileHeight);
}
window.addEventListener('resize', syncMobileHeight);

/* ── Character Counter ───────────────────────────────────────────────────────── */

function attachCharCounter(input, counterId) {
    const counter = $(counterId); if (!counter) return;
    const max = input.maxLength > 0 ? input.maxLength : 1000;
    const update = () => {
        const len = input.value.length, rem = max - len;
        counter.textContent = len > 0 ? rem + ' left' : '';
        counter.className = 'char-counter'
            + (rem < 100 ? ' char-warn' : '')
            + (rem < 20 ? ' char-danger' : '');
    };
    input.addEventListener('input', update);
}

/* ── Password Show / Hide ────────────────────────────────────────────────────── */

function initPasswordToggles() {
    document.querySelectorAll('.pass-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
            const inp = $(btn.dataset.target); if (!inp) return;
            const show = inp.type === 'password';
            inp.type = show ? 'text' : 'password';
            btn.textContent = show ? '◎' : '●';
            btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
            btn.title = show ? 'Hide' : 'Show';
        });
    });
}

/* ── Nickname UI — Inline Popover ────────────────────────────────────────────── */

function buildNicknameUI() {
    const nickBtn = document.createElement('button');
    nickBtn.id = 'nick-btn';
    nickBtn.className = 'nick-btn';
    nickBtn.title = 'Change nickname';
    nickBtn.setAttribute('aria-haspopup', 'dialog');
    nickBtn.setAttribute('aria-expanded', 'false');
    updateNickBtnLabel(nickBtn, getNickname(S.isHost));
    $('title-bar').insertBefore(nickBtn, $('win-conn-badge'));

    const popover = $('nick-popover');
    const nickInput = $('nick-popover-input');
    const saveBtn = $('nick-popover-save');

    function openPopover() {
        nickInput.value = getNickname(S.isHost);
        popover.classList.remove('d-none'); popover.hidden = false;
        nickBtn.setAttribute('aria-expanded', 'true');
        nickInput.focus(); nickInput.select();
    }
    function closePopover() {
        popover.classList.add('d-none'); popover.hidden = true;
        nickBtn.setAttribute('aria-expanded', 'false');
    }
    function commitNick() {
        const nick = nickInput.value.trim().slice(0, 32);
        if (!nick) { toast('Nickname cannot be empty'); return; }
        saveNickname(S.isHost, nick);
        updateNickBtnLabel(nickBtn, nick);
        closePopover();
    }

    nickBtn.addEventListener('click', e => { e.stopPropagation(); openPopover(); });
    saveBtn.addEventListener('click', e => { e.stopPropagation(); commitNick(); });
    nickInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); commitNick(); }
        if (e.key === 'Escape') { closePopover(); }
    });
    document.addEventListener('click', e => {
        if (!popover.classList.contains('d-none') &&
            !popover.contains(e.target) && e.target !== nickBtn) closePopover();
    });
}

function updateNickBtnLabel(btn, nick) {
    btn.textContent = nick ? '✎ ' + nick : '✎ set name';
}

/* ── WebSocket ───────────────────────────────────────────────────────────────── */

let ws2, rtimer, rdelay = 2000;
let keepAliveInterval = null;

function connect() {
    if (ws2 && ws2.readyState < 2) return;
    if (location.protocol !== 'https:' &&
        location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
        console.warn('[tunel] HTTPS required for production E2EE.');
    }
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    try { ws2 = new WebSocket(proto + '//' + location.host + '/ws'); S.ws = ws2; }
    catch { sched(); return; }
    ws2.addEventListener('open', onOpen);
    ws2.addEventListener('message', e => { try { onMsg(JSON.parse(e.data)); } catch { } });
    ws2.addEventListener('close', onClose);
    ws2.addEventListener('error', () => { });
}

function onOpen() {
    rdelay = 2000; clearTimeout(rtimer); setBadge('online', 'connected');
    stepsReset(); stepSet('cstep-ws', 'active');
    if (S.isHost) { showView('host-login'); setBadge('host', 'waiting'); updateHostUI(); }
    else { startVisitor(); }
}

function onClose() {
    setBadge('offline', 'disconnected');
    stopKeepAlive();
    stepsReset();
    if (S.isHost) S._sessionActive = false;
    if (!S.isHost && !S.chatReady) clrEnc();
    sched();
}

function sched() {
    clearTimeout(rtimer);
    rtimer = setTimeout(() => { rdelay = Math.min(rdelay * 1.5, 30_000); connect(); }, rdelay);
}

function wsSend(obj) { if (ws2 && ws2.readyState === 1) ws2.send(JSON.stringify(obj)); }

function startKeepAlive() {
    stopKeepAlive();
    keepAliveInterval = setInterval(() => {
        if (ws2 && ws2.readyState === 1) wsSend({ type: '__ping' });
    }, 25_000);
}
function stopKeepAlive() {
    if (keepAliveInterval) { clearInterval(keepAliveInterval); keepAliveInterval = null; }
}

/* ── Visitor Flow ────────────────────────────────────────────────────────────── */

async function startVisitor() {
    if (!S.chatReady) { showView('connecting'); setBadge('connecting', 'waiting'); }
    else { setBadge('connecting', 'waiting'); }

    stepDone('cstep-ws');  // WS opened, now generating keys

    try {
        S.kp = await genKeyPair(); S.sc = 0; S.rc = -1; S.sessionKey = null; S.fp = null;
        stepDone('cstep-key');  // keys generated, now exchanging
        wsSend({ type: 'visitor_hello', vid: S.vid, nick: getNickname(false) });
    } catch (e) {
        showView('chat');
        addSys($('messages'), 'Crypto init failed: ' + e.message, 'error');
    }
}

async function visitorMsg(msg) {
    switch (msg.type) {

        case 'visitor_welcome':
            S.vid = msg.vid;
            localStorage.setItem(LS_VID, msg.vid);
            break;

        case 'host_online':
            if (msg.nick) S._peerNick = msg.nick;
            wsSend({ type: 'visitor_key', pubkey: await exportPub(S.kp) });
            setBadge('key exchange', 'waiting');
            break;

        case 'host_key': {
            const hp = await importPub(msg.pubkey);
            const { key, fp } = await deriveSessionKey(S.kp.privateKey, hp);
            S.sessionKey = key; S.fp = fp;
            const wasReady = S.chatReady; S.chatReady = true;
            stepDone('cstep-exchange');
            showView('chat');
            $('msg-input').disabled = false; $('send-btn').disabled = false;
            setBadge('encrypted', 'connected'); setEnc(fp);
            if (!wasReady) {
                addSys($('messages'), '🔒 Secure channel established', 'good');
                addSys($('messages'), 'Fingerprint: ' + fp);
                startKeepAlive();
            } else {
                addSys($('messages'), '🔒 Session re-keyed · FP: ' + fp, 'good');
            }
            break;
        }

        case 'host_offline':
            S._hostPub = msg.hostPubkey || null;
            S.chatReady = false;
            showView('offline'); setBadge('offline', 'disconnected');
            break;

        case 'chat': {
            if (!S.sessionKey) break;
            try {
                const { t, n, ts } = await decMsg(S.sessionKey, msg.iv, msg.ciphertext);
                if (n <= S.rc) { addSys($('messages'), '⚠ Replay detected', 'warn'); break; }
                S.rc = n;
                addMsg($('messages'), t, false, ts, msg.nick || S._peerNick || null, msg.mid);
                if (msg.mid) wsSend({ type: 'msg_ack', mid: msg.mid });
                sounds.incomingMessage();
            } catch (e) {
                console.error('[tunel] decrypt:', e);
                addSys($('messages'), '⚠ Decryption failed', 'warn');
            }
            break;
        }

        case 'nick_update':
            if (S._peerNick === msg.nick) break;
            S._peerNick = msg.nick;
            addSys($('messages'), 'Host is now: ' + (msg.nick || 'Anonymous'));
            break;

        case 'msg_ack':
            markRead($('messages'), msg.mid);
            break;

        case 'host_disconnected':
            addSys($('messages'), 'Host disconnected', 'warn');
            $('msg-input').disabled = true; $('send-btn').disabled = true;
            clrEnc(); setBadge('offline', 'disconnected');
            break;
    }
}

async function sendVisitor() {
    const inp = $('msg-input'), text = inp.value.trim();
    if (!text || !S.sessionKey) return;
    const btn = $('send-btn');
    if (btn.disabled) return;
    btn.disabled = true;
    setTimeout(() => { if (S.sessionKey) btn.disabled = false; }, 1000);
    inp.value = ''; adjTA(inp);
    try {
        const mid = uid(), nick = getNickname(false);
        const e2 = await encMsg(S.sessionKey, text, ++S.sc);
        wsSend({ type: 'chat', ...e2, nick: nick || undefined, mid });
        addMsg($('messages'), text, true, Date.now(), nick || null, mid);
    } catch {
        addSys($('messages'), 'Failed to send', 'error');
        sounds.error(); btn.disabled = false;
    }
}

/* ── Offline Message Send ────────────────────────────────────────────────────── */

$('off-send-btn').addEventListener('click', async () => {
    const name = $('off-name').value.trim().slice(0, 100);
    const contact = $('off-contact').value.trim().slice(0, 200);
    const message = $('off-msg').value.trim().slice(0, 1000);
    if (!name || !contact || !message) {
        $('off-status').textContent = 'Please fill in all fields.'; return;
    }
    $('off-send-btn').disabled = true;
    $('off-status').textContent = 'Encrypting…';
    await processOfflineSend(name, contact, message);
});

async function processOfflineSend(name, contact, message) {
    try {
        let hp = S._hostPub;
        if (!hp || !hp.length) {
            wsSend({ type: 'request_host_pubkey' });
            S._pendingSend = { name, contact, message };
            $('off-status').textContent = 'Fetching public key…';
            return;
        }
        await doSendOffline(hp, { name, contact, message });
    } catch (e) {
        $('off-status').textContent = 'Error: ' + e.message;
        $('off-send-btn').disabled = false;
        sounds.error();
    }
}

async function doSendOffline(hp, payload) {
    const blob = await encryptOffline(hp, payload);
    wsSend({ type: 'offline_message', ...blob });
}

function showOfflineSuccess() {
    sounds.success();
    const fw = $('offline-form-wrap'), su = $('offline-success');
    fw.classList.add('tv-off');
    setTimeout(() => { fw.classList.add('d-none'); su.classList.add('visible'); }, 470);
}

/* ── Host Login & Vault ──────────────────────────────────────────────────────── */

function updateHostUI() {
    const exists = S.vaultExists;
    $('host-login-title').textContent = exists ? 'Unlock Vault' : 'Set Up Host';
    $('master-pass-label').textContent = exists ? 'Master Password' : 'Set Master Password';
    $('host-login-btn').textContent = exists ? 'Unlock & Connect' : 'Initialize Vault';
    $('host-setup-fields').classList.toggle('d-none', exists);
    $('vault-reset-wrap').classList.toggle('d-none', !exists);
    $('host-login-btn').disabled = false;
    $('host-login-btn').classList.remove('btn-loading');
}

$('vault-reset-btn').addEventListener('click', () => {
    if (confirm(
        'Delete your identity vault?\n\n' +
        'You will permanently lose the ability to decrypt offline messages\n' +
        'that were encrypted to your current long-term public key.'
    )) {
        ['tunel_vault', 'tunel_vault_meta', 'tunel_vault_salt'].forEach(k => localStorage.removeItem(k));
        S.vaultExists = false; S._sessionActive = false;
        updateHostUI();
    }
});

$('host-login-btn').addEventListener('click', doLogin);
$('host-token-input').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
$('host-lt-pass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

async function doLogin() {
    const btn = $('host-login-btn');
    const err = $('login-error');
    const pass = $('host-lt-pass').value;  // do NOT trim — passwords may include spaces
    if (!pass) { toast('Master password is required'); return; }

    const originalLabel = btn.textContent;
    btn.disabled = true; btn.classList.add('btn-loading'); btn.textContent = '';
    err.classList.add('d-none');

    try {
        if (S.vaultExists) {
            const vault = await loadVault(pass);
            S._hostToken = vault.token; S.ltPass = pass;
            S.ltKey = { privateKey: vault.ltKeyPair.privateKey, pubBytes: vault.pubBytes };
            localStorage.setItem(LS_NICK_HOST, vault.nick);
            wsSend({ type: 'host_auth', token: vault.token, nick: vault.nick });
        } else {
            const nick = $('host-nick-input').value.trim();
            const token = $('host-token-input').value.trim();
            if (!nick || !token) {
                btn.textContent = originalLabel; btn.disabled = false;
                btn.classList.remove('btn-loading');
                toast('Name and access token are both required'); return;
            }
            const kp = await genLTPair();
            await saveVault(pass, token, nick, kp);
            S._hostToken = token; S.ltPass = pass;
            S.ltKey = {
                privateKey: kp.privateKey,
                pubBytes: Array.from(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))),
            };
            localStorage.setItem(LS_NICK_HOST, nick);
            wsSend({ type: 'host_auth', token, nick });
        }
    } catch (e) {
        err.textContent = e.message; err.classList.remove('d-none');
        btn.textContent = originalLabel; btn.disabled = false;
        btn.classList.remove('btn-loading');
        sounds.error();
    }
}

/* ── Host Incoming Messages ──────────────────────────────────────────────────── */

async function hostMsg(msg) {
    switch (msg.type) {

        case 'auth_success': {
            S._sessionActive = true;
            showView('host-dash'); setBadge('host', 'connected');
            startKeepAlive();
            if (S.ltKey) wsSend({ type: 'host_set_longterm_pubkey', pubkey: S.ltKey.pubBytes });
            if (msg.offlineMessages?.length) renderOffline(msg.offlineMessages);
            const nickBtn = $('nick-btn');
            if (nickBtn) updateNickBtnLabel(nickBtn, getNickname(true));
            if (!S._authToastShown) { toast('Host session active'); S._authToastShown = true; }
            updateHostUI();  // restore button label + state
            break;
        }

        case 'auth_failed':
            S._hostToken = null; S.ltPass = null; S._sessionActive = false;
            $('login-error').textContent = 'Invalid token — check your HOST_TOKEN.';
            $('login-error').classList.remove('d-none');
            $('host-token-input').value = '';
            showView('host-login'); updateHostUI();
            sounds.error();
            break;

        case 'visitor_waiting': {
            const vid = msg.visitorId; if (!vid) break;
            const nick = msg.nick || null;
            if (!S.sessions.has(vid)) {
                const kp = await genKeyPair(), pub = await exportPub(kp);
                S.sessions.set(vid, { kp, key: null, fp: null, sc: 0, rc: -1, msgs: [], nick });
                wsSend({ type: 'host_key', to: vid, pubkey: pub });
                addVisitor(vid, nick); toast('New visitor connected');
            } else {
                const sess = S.sessions.get(vid);
                if (sess.offline) {
                    sess.offline = false;
                    $('vi-' + vid)?.classList.remove('offline');
                    toast('Visitor reconnected');
                }
                const kp = await genKeyPair(), pub = await exportPub(kp);
                sess.kp = kp; sess.key = null; sess.fp = null; sess.sc = 0; sess.rc = -1;
                wsSend({ type: 'host_key', to: vid, pubkey: pub });
            }
            break;
        }

        case 'visitor_key': {
            const vid = msg.visitorId, sess = S.sessions.get(vid); if (!sess) break;
            const vp = await importPub(msg.pubkey);
            const { key, fp } = await deriveSessionKey(sess.kp.privateKey, vp);
            const wasReady = sess.status === 'ready';
            sess.key = key; sess.fp = fp; sess.status = 'ready';
            if (S.activeVid === vid) {
                setEnc(fp);
                $('msg-input-host').disabled = false; $('send-btn-host').disabled = false;
                if (!wasReady) {
                    addSys($('messages-host'), '🔒 Secure channel established', 'good');
                    addSys($('messages-host'), 'Fingerprint: ' + fp);
                } else {
                    addSys($('messages-host'), '🔒 Session re-keyed · FP: ' + fp, 'good');
                }
            }
            break;
        }

        case 'chat': {
            const vid = msg.from, sess = S.sessions.get(vid); if (!sess || !sess.key) break;
            try {
                const { t, n, ts } = await decMsg(sess.key, msg.iv, msg.ciphertext);
                if (n <= sess.rc) break; sess.rc = n;
                const nick = msg.nick || sess.nick || null;
                sess.msgs.push({ text: t, own: false, ts, nick, mid: msg.mid, acked: S.activeVid === vid });
                if (S.activeVid === vid) {
                    addMsg($('messages-host'), t, false, ts, nick, msg.mid);
                    if (msg.mid) wsSend({ type: 'msg_ack', mid: msg.mid, to: vid });
                } else {
                    markUnread(vid);
                }
                sounds.incomingMessage();
            } catch { if (S.activeVid === vid) addSys($('messages-host'), '⚠ Decryption failed', 'warn'); }
            break;
        }

        case 'nick_update': {
            const vid = msg.from, sess = S.sessions.get(vid);
            if (sess && sess.nick !== msg.nick) {
                sess.nick = msg.nick;
                updateVisitorLabel(vid, msg.nick);
                if (S.activeVid === vid)
                    addSys($('messages-host'), 'Visitor is now: ' + (msg.nick || 'Anonymous'));
            }
            break;
        }

        case 'msg_ack': {
            const sess = S.sessions.get(msg.from);
            if (sess) {
                const m = sess.msgs.find(x => x.mid === msg.mid);
                if (m) m.read = true;
                if (S.activeVid === msg.from) markRead($('messages-host'), msg.mid);
            }
            break;
        }

        case 'visitor_disconnected': {
            const vid = msg.visitorId; if (!vid) break;
            const sess = S.sessions.get(vid);
            if (sess) {
                if (sess.msgs.length === 0) {
                    S.sessions.delete(vid); rmVisitor(vid);
                    if (S.activeVid === vid) {
                        S.activeVid = null; clearOfflineChatUI();
                        $('messages-host').innerHTML = '';
                        $('msg-input-host').disabled = true; $('send-btn-host').disabled = true;
                        clrEnc();
                    }
                } else {
                    sess.offline = true;
                    $('vi-' + vid)?.classList.add('offline');
                    if (S.activeVid === vid) {
                        addSys($('messages-host'), 'Visitor disconnected — session preserved', 'warn');
                        $('msg-input-host').disabled = true; $('send-btn-host').disabled = true;
                        clrEnc();
                    }
                }
            }
            toast('Visitor left');
            break;
        }

        case 'new_offline_message':
            renderOffline(msg.offlineMessages || []);
            toast('New offline message received');
            break;

        case 'offline_cleared':
            renderOffline([]);
            break;
    }
}

async function sendHost() {
    const vid = S.activeVid, sess = S.sessions.get(vid);
    if (!sess || !sess.key || sess.offline) return;
    const inp = $('msg-input-host'), text = inp.value.trim(); if (!text) return;
    const btn = $('send-btn-host');
    if (btn.disabled) return;
    btn.disabled = true;
    setTimeout(() => { if (S.activeVid === vid && sess.key && !sess.offline) btn.disabled = false; }, 1000);
    inp.value = ''; adjTA(inp);
    try {
        const mid = uid(), nick = getNickname(true);
        const e2 = await encMsg(sess.key, text, ++sess.sc);
        wsSend({ type: 'chat', to: vid, ...e2, nick: nick || undefined, mid });
        addMsg($('messages-host'), text, true, Date.now(), nick || null, mid);
        sess.msgs.push({ text, own: true, ts: Date.now(), nick: nick || null, mid });
    } catch {
        addSys($('messages-host'), 'Send failed', 'error');
        sounds.error(); btn.disabled = false;
    }
}

/* ── Unread Badges ───────────────────────────────────────────────────────────── */

function markUnread(vid) {
    const count = (S.unread.get(vid) || 0) + 1;
    S.unread.set(vid, count);
    const item = $('vi-' + vid); if (!item) return;
    item.classList.add('has-unread');
    let badge = item.querySelector('.unread-counter');
    if (!badge) {
        badge = document.createElement('span'); badge.className = 'unread-badge unread-counter';
        item.appendChild(badge);
    }
    badge.textContent = count;
}
function clearUnread(vid) {
    S.unread.delete(vid);
    const item = $('vi-' + vid); if (!item) return;
    item.classList.remove('has-unread');
    item.querySelector('.unread-counter')?.remove();
}

/* ── Visitor Sidebar ─────────────────────────────────────────────────────────── */

function addVisitor(vid, nick) {
    if (!vid || $('vi-' + vid)) return;
    const list = $('visitor-list');
    list.querySelector('.muted-ph')?.remove();

    const item = document.createElement('div'); item.className = 'visitor-item'; item.id = 'vi-' + vid;
    const dot = document.createElement('div'); dot.className = 'visitor-dot-static';
    const lbl = document.createElement('span'); lbl.className = 'v-lbl';
    lbl.textContent = nick || ('visitor ' + vid.slice(0, 6));

    const rm = document.createElement('div'); rm.className = 'v-rm';
    rm.textContent = '×'; rm.title = 'Remove conversation';
    rm.addEventListener('click', e => {
        e.stopPropagation();
        if (confirm('Remove this conversation from history?')) {
            S.sessions.delete(vid); rmVisitor(vid);
            if (S.activeVid === vid) {
                S.activeVid = null; clearOfflineChatUI();
                $('messages-host').innerHTML = '';
                $('msg-input-host').disabled = true; $('send-btn-host').disabled = true;
                clrEnc();
            }
        }
    });

    item.appendChild(dot); item.appendChild(lbl); item.appendChild(rm);
    list.appendChild(item);
    item.addEventListener('click', () => switchVid(vid));
    if (!S.activeVid) switchVid(vid);
}

function updateVisitorLabel(vid, nick) {
    const lbl = $('vi-' + vid)?.querySelector('.v-lbl');
    if (lbl) lbl.textContent = nick || ('visitor ' + vid.slice(0, 6));
}

function rmVisitor(vid) {
    $('vi-' + vid)?.remove();
    if (!$('visitor-list').children.length) {
        const ph = document.createElement('span'); ph.className = 'muted-ph'; ph.textContent = 'None';
        $('visitor-list').appendChild(ph);
    }
}

function switchVid(vid) {
    S.activeVid = vid; const sess = S.sessions.get(vid);
    document.querySelectorAll('.visitor-item').forEach(e => e.classList.remove('active'));
    $('vi-' + vid)?.classList.add('active');
    clearUnread(vid); clearOfflineChatUI();

    const box = $('messages-host'); box.innerHTML = '';
    if (sess) {
        sess.msgs.forEach(m => { addMsg(box, m.text, m.own, m.ts, m.nick || null, m.mid); if (m.own && m.read) markRead(box, m.mid); });
        sess.msgs.filter(m => !m.own && !m.acked).forEach(m => {
            if (m.mid) { wsSend({ type: 'msg_ack', mid: m.mid, to: vid }); m.acked = true; }
        });
        if (sess.key) {
            $('msg-input-host').disabled = false; $('send-btn-host').disabled = false; setEnc(sess.fp);
        } else {
            $('msg-input-host').disabled = true; $('send-btn-host').disabled = true; clrEnc();
            addSys(box, 'Completing key exchange…');
        }
    }
}

/* ── Offline Messages ────────────────────────────────────────────────────────── */

function renderOffline(messages) {
    const list = $('offline-list'); list.innerHTML = '';
    if (!messages.length) {
        const ph = document.createElement('span'); ph.className = 'muted-ph'; ph.textContent = 'None';
        list.appendChild(ph); return;
    }
    messages.forEach(m => {
        const card = document.createElement('div'); card.className = 'offline-card';
        const lbl = document.createElement('div'); lbl.className = 'offline-card-label';
        lbl.textContent = new Date(m.ts).toLocaleString();
        const txt = document.createElement('div'); txt.className = 'offline-card-text';
        txt.textContent = '[encrypted — click to decrypt]';
        card.appendChild(lbl); card.appendChild(txt); list.appendChild(card);
        let data = null;
        card.addEventListener('click', async () => {
            if (card.classList.contains('decrypted') && data) { openOfflineChat(data, m.ts); return; }
            if (card.classList.contains('decrypted')) return;
            if (!S.ltKey) { txt.textContent = 'Vault not unlocked.'; return; }
            try {
                txt.textContent = 'Decrypting…';
                data = await decryptOffline(S.ltKey.privateKey, m.senderPubkey, m.iv, m.ciphertext);
                card.classList.add('decrypted'); txt.textContent = '';
                const nm = document.createElement('div'); nm.className = 'offline-card-name-title'; nm.textContent = data.name || '—';
                const ct = document.createElement('div'); ct.className = 'offline-card-contact-title'; ct.textContent = data.contact || '';
                const ob = document.createElement('button'); ob.className = 'offline-open-btn'; ob.textContent = '↗ open in chat';
                txt.appendChild(nm); txt.appendChild(ct); txt.appendChild(ob);
                ob.addEventListener('click', e => { e.stopPropagation(); openOfflineChat(data, m.ts); });
                openOfflineChat(data, m.ts);
            } catch (e) { txt.textContent = 'Decryption failed: ' + e.message; }
        });
    });
}

function clearOfflineChatUI() {
    $('host-chat-area').querySelector('.offline-chat-header')?.remove();
}

function openOfflineChat(data, ts) {
    document.querySelectorAll('.visitor-item').forEach(e => e.classList.remove('active'));
    S.activeVid = null;
    $('msg-input-host').disabled = true; $('send-btn-host').disabled = true; clrEnc();
    clearOfflineChatUI();

    const ca = $('host-chat-area'), box = $('messages-host');
    const hdr = document.createElement('div'); hdr.className = 'offline-chat-header';
    const badge = document.createElement('span'); badge.className = 'offline-chat-badge'; badge.textContent = 'offline msg';
    const name = document.createElement('span'); name.className = 'offline-chat-name'; name.textContent = data.name || 'Anonymous';
    const contact = document.createElement('span'); contact.className = 'offline-chat-contact'; contact.textContent = data.contact || '';
    const time = document.createElement('span'); time.className = 'offline-chat-time'; time.textContent = new Date(ts).toLocaleString();
    const left = document.createElement('div'); left.className = 'offline-chat-header-left';
    left.appendChild(badge); left.appendChild(name); left.appendChild(contact);
    hdr.appendChild(left); hdr.appendChild(time);
    ca.insertBefore(hdr, box);

    box.innerHTML = '';
    addSys(box, '🔒 End-to-end encrypted offline message', 'good');
    addMsg(box, data.message || '', false, ts);
}

$('clear-offline-btn').addEventListener('click', () => {
    if (confirm('Permanently delete all offline messages?')) {
        wsSend({ type: 'host_clear_offline' });
        clearOfflineChatUI(); $('messages-host').innerHTML = '';
    }
});

/* ── Unified Message Handler ─────────────────────────────────────────────────── */

async function onMsg(msg) {
    if (typeof msg !== 'object' || !msg.type) return;

    if (msg.type === 'server_hello') {
        const key = 'tunel_server_id_' + location.host;
        const stored = localStorage.getItem(key);
        if (stored && stored !== msg.pubkey) {
            alert(
                'SECURITY WARNING: Server identity has changed!\n\n' +
                'This may indicate a man-in-the-middle attack.\n\n' +
                'Expected: ' + stored.slice(0, 20) + '…\n' +
                'Received: ' + msg.pubkey.slice(0, 20) + '…\n\n' +
                'If you redeployed the server intentionally, clear the stored identity:\n' +
                'localStorage.removeItem("' + key + '")'
            );
            ws2?.close(); return;
        }
        localStorage.setItem(key, msg.pubkey);
        stepDone('cstep-ws');
        return;
    }

    if (msg.type === 'host_pubkey' && S._pendingSend) {
        const pending = S._pendingSend; S._pendingSend = null;
        if (msg.pubkey?.length) {
            S._hostPub = msg.pubkey;
            try { await doSendOffline(msg.pubkey, pending); }
            catch (e) { $('off-status').textContent = 'Error: ' + e.message; $('off-send-btn').disabled = false; sounds.error(); }
        } else {
            $('off-status').textContent = 'Host has not registered a public key yet.';
            $('off-send-btn').disabled = false;
        }
        return;
    }

    if (msg.type === 'offline_message_saved') { showOfflineSuccess(); return; }

    if (msg.type === 'error') {
        if (msg.message?.includes('Replaced by new session')) {
            alert('Your host session was replaced by a new login from another device.');
            location.reload(); return;
        }
        toast('Server: ' + msg.message);
        return;
    }

    if (msg.type === '__pong') return;

    if (S.isHost) await hostMsg(msg); else await visitorMsg(msg);
}

/* ── Input Handling ──────────────────────────────────────────────────────────── */

function adjTA(el) { el.style.height = 'auto'; el.style.height = Math.min(el.scrollHeight, 120) + 'px'; }

$('msg-input').addEventListener('input', function () { adjTA(this); });
$('msg-input').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendVisitor(); } });
$('msg-input').addEventListener('focus', () => setTimeout(syncMobileHeight, 400));
$('send-btn').addEventListener('click', sendVisitor);

$('msg-input-host').addEventListener('input', function () { adjTA(this); });
$('msg-input-host').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendHost(); } });
$('msg-input-host').addEventListener('focus', () => setTimeout(syncMobileHeight, 400));
$('send-btn-host').addEventListener('click', sendHost);

/* ── SVG Logo Patch ──────────────────────────────────────────────────────────── */
// Inline each <svg use="#tunel-logo"> to work around cross-browser gradient-scoping
// bugs in <symbol> elements when the containing <svg> is display:none.

function patchLogoSVG() {
    const NS = 'http://www.w3.org/2000/svg';
    document.querySelectorAll('svg use[href="#tunel-logo"]').forEach((use, i) => {
        const svg = use.closest('svg'); if (!svg) return;
        svg.innerHTML = '';
        if (!svg.getAttribute('viewBox')) svg.setAttribute('viewBox', '0 0 48 48');

        const defs = document.createElementNS(NS, 'defs');
        const mkGrad = (id, x1, y1, x2, y2, c1, c2) => {
            const g = document.createElementNS(NS, 'linearGradient');
            g.id = id + '_' + i;
            g.setAttribute('x1', x1); g.setAttribute('y1', y1);
            g.setAttribute('x2', x2); g.setAttribute('y2', y2);
            [[c1, '0%'], [c2, '100%']].forEach(([col, off]) => {
                const s = document.createElementNS(NS, 'stop');
                s.setAttribute('offset', off); s.setAttribute('stop-color', col);
                g.appendChild(s);
            });
            return g;
        };
        defs.appendChild(mkGrad('lg1', '0%', '0%', '100%', '100%', '#a78bfa', '#60a5fa'));
        defs.appendChild(mkGrad('lg2', '100%', '0%', '0%', '100%', '#f472b6', '#7c6af7'));
        svg.appendChild(defs);

        const rect = document.createElementNS(NS, 'rect');
        rect.setAttribute('width', '48'); rect.setAttribute('height', '48');
        rect.setAttribute('rx', '11'); rect.setAttribute('fill', '#1a1240');
        svg.appendChild(rect);

        const mkPath = (d, grad, sw, opacity) => {
            const p = document.createElementNS(NS, 'path');
            p.setAttribute('d', d); p.setAttribute('stroke', `url(#${grad}_${i})`);
            p.setAttribute('stroke-width', sw); p.setAttribute('fill', 'none');
            p.setAttribute('stroke-linecap', 'round');
            if (opacity) p.setAttribute('opacity', opacity);
            return p;
        };
        svg.appendChild(mkPath('M10 38 L10 16 Q10 11 15 11 Q19 11 20.5 15', 'lg1', '3.8'));
        svg.appendChild(mkPath('M20.5 15 Q23 10 28 10 Q38 10 38 20 L38 38', 'lg1', '3.8'));
        svg.appendChild(mkPath('M10 20 Q17 28 24 24 Q31 20 38 28', 'lg2', '2', '0.7'));

        [[10, 38], [38, 38]].forEach(([cx, cy]) => {
            const c = document.createElementNS(NS, 'circle');
            c.setAttribute('cx', cx); c.setAttribute('cy', cy);
            c.setAttribute('r', '2.5'); c.setAttribute('fill', `url(#lg1_${i})`);
            svg.appendChild(c);
        });
    });
}

/* ── Viewport Fix ────────────────────────────────────────────────────────────── */

function patchViewport() {
    const v = document.querySelector('meta[name="viewport"]');
    if (v && !v.content.includes('interactive-widget'))
        v.content += ', interactive-widget=resizes-content';
}

/* ── Boot ────────────────────────────────────────────────────────────────────── */

$('msg-input').maxLength = 1000;
$('msg-input-host').maxLength = 1000;
$('off-msg').maxLength = 1000;

patchLogoSVG();
patchViewport();
buildNicknameUI();
initPasswordToggles();

attachCharCounter($('msg-input'), 'msg-counter');
attachCharCounter($('msg-input-host'), 'msg-host-counter');
attachCharCounter($('off-msg'), 'off-msg-counter');

$('setup-nick-input').addEventListener('keydown', e => { if (e.key === 'Enter') $('setup-start-btn').click(); });
$('setup-start-btn').addEventListener('click', () => {
    const nick = $('setup-nick-input').value.trim();
    if (!nick) { toast('Nickname is required'); return; }
    saveNickname(false, nick);
    showView('connecting'); connect();
});

function boot() {
    centerWin();
    if (S.isHost) { updateHostUI(); showView('host-login'); connect(); }
    else {
        const nick = getNickname(false);
        if (!nick) showView('setup');
        else { showView('connecting'); connect(); }
    }
}

boot();
syncMobileHeight();
