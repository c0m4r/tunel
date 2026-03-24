# 🔐 tunel — End-to-End Encrypted Chat

A self-hosted, browser-based chat with true end-to-end encryption. The server is a
**dumb relay** — it never sees plaintext. All cryptography runs in the browser via the
native WebCrypto API. No dependencies beyond Node.js and the `ws` library.

---

## Security Architecture

```
Visitor browser                Server (relay only)              Host browser
─────────────────              ───────────────────              ────────────────
Generate ECDH P-256 ──pubkey──▶ store & forward ──pubkey──▶   Generate ECDH P-256
Derive shared secret                                            Derive shared secret
  (never transmitted)                                             (never transmitted)
Derive AES-256-GCM key                                          Derive AES-256-GCM key
Encrypt with random IV ──🔒──▶ relays ciphertext ──🔒──▶       Decrypt
```

### Cryptographic Primitives

| Primitive       | Usage                                | Standard  |
|-----------------|--------------------------------------|-----------|
| ECDH P-256      | Ephemeral session key agreement      | NIST SP 800-56A |
| HKDF-SHA-256    | Key derivation from shared secret    | RFC 5869  |
| AES-256-GCM     | Authenticated message encryption     | FIPS 197  |
| PBKDF2-SHA-256  | Master password key derivation       | NIST SP 800-132|
| SHA-256         | Session fingerprint                  | FIPS 180-4|
| WebCrypto API   | All crypto operations (browser)      | W3C       |

### Security Properties

- **Identity Vault** — Host's sensitive data (access token, long-term keys) is stored
  encrypted in `localStorage` using a Master Password. It is never stored in plaintext.
- **Forward secrecy** — ephemeral ECDH keys per session; compromise of one session
  does not affect others
- **Authenticated encryption** — AES-GCM provides both confidentiality and integrity;
  tampered messages are rejected
- **Replay protection** — encrypted payload includes a monotonic counter; out-of-order
  messages are dropped
- **MITM detection** — both parties display a session fingerprint (SHA-256 of the ECDH
  shared secret); verify this out-of-band to confirm no interception
- **Offline message E2E** — offline messages are encrypted to the host's long-term
  ECDH public key; even the server cannot read them
- **Timing-safe auth** — host token comparison uses `crypto.timingSafeEqual`
- **Zero plaintext on server** — server only ever stores/forwards encrypted blobs
- **No logging** — server never logs message content

### Threat Model

| Threat                       | Mitigation                                      |
|------------------------------|-------------------------------------------------|
| Network eavesdropper         | TLS (WSS) + AES-256-GCM                         |
| Compromised server           | Server never sees plaintext; only encrypted blobs|
| MITM on key exchange         | Session fingerprint — verify out-of-band         |
| Replay attack                | Per-session message counter in encrypted payload |
| XSS → message theft          | Strict CSP; `textContent` never `innerHTML`      |
| Brute-force host token       | Timing-safe compare; rate limiting; conn closed  |
| DoS / flood                  | Per-IP rate limiting (HTTP + WS); 128 KB max msg |
| Offline message snooping     | Encrypted to host long-term pubkey               |

---

## Installation

**Requirements:** Node.js ≥ 24.0.0

```bash
npm install
```

---

## Configuration

Set a strong, secret token for host authentication:

```bash
export HOST_TOKEN="$(openssl rand -hex 32)"
echo "HOST_TOKEN=$HOST_TOKEN" >> .env    # save it!
```

If `HOST_TOKEN` is not set, a random one is generated each run and printed to stdout.

**Optional:**

```bash
export PORT=3000    # default: 3000
```

---

## Running

```bash
# Production
HOST_TOKEN=your_secret_token node server.js

# Development (auto-restart on change, Node ≥ 18)
HOST_TOKEN=your_secret_token npm run dev
```

---

## Deployment (Production Checklist)

- [ ] **Enable TLS** — run behind nginx/Caddy with a valid certificate.
      WebSockets will automatically upgrade to WSS.
- [ ] **Uncomment HSTS** in `server.js` once TLS is confirmed working.
- [ ] **Set `HOST_TOKEN`** as an environment variable (not in source code).
- [ ] **Reverse proxy** example (nginx):
      ```nginx
      location / {
          proxy_pass         http://localhost:3000;
          proxy_http_version 1.1;
          proxy_set_header   Upgrade $http_upgrade;
          proxy_set_header   Connection "upgrade";
          proxy_set_header   Host $host;
          proxy_set_header   X-Forwarded-For $remote_addr;
          proxy_set_header   X-Real-IP $remote_addr;
      }
      ```
- [ ] **Firewall** — expose only 80/443; block direct access to port 3000.
- [ ] **Process manager** — use `pm2` or a systemd service for auto-restart.

---

## Usage

### As a Visitor

Navigate to your site URL. The chat window opens automatically. If you're online,
a secure encrypted session is established within seconds. Verify the **session
fingerprint** displayed in the status bar with the host out-of-band for maximum
assurance.

If you're offline, a "Leave a Secure Message" form appears. Your message — including
your name and contact details — is encrypted in your browser before transmission.
The server stores only the encrypted blob.

### As the Host

Navigate to `https://example.com/#/mode/host`  
On first visit, you will be prompted to set up your **Identity Vault**:
1. Enter your **Nickname**
2. Enter the **Access Token** (`HOST_TOKEN`)
3. Set a **Master Password** to protect your identity and data.

On subsequent visits, you only need your **Master Password** to unlock the vault and start chatting.

The host dashboard shows:
- **Live Visitors** — connected users with active encrypted sessions
- **Offline Messages** — encrypted blobs you can decrypt in-browser by clicking them

### Session Fingerprint Verification

Both you and your visitor see the same 8-byte fingerprint in the status bar.
If they match (verified via phone call, Signal, etc.), you are protected against MITM.
If they differ, assume the session is compromised.

---

## Known Limitations

1. **Browser Persistent Storage** — the identity vault is stored in `localStorage`.
   If the browser cache is cleared, you will need to re-initialize with your Nickname and Token.
2. **Single-host design** — designed for one host and multiple visitors. Multi-host
   is not supported.
3. **No message persistence** — live chat messages are not stored anywhere.
   If either party refreshes, the conversation is lost.
4. **No perfect forward secrecy for offline messages** — offline messages are
   encrypted to the host's long-term key. If that key is ever compromised, old
   offline messages could be decrypted.

---

## License

WTFPL