# SecureChat — Zero-Knowledge E2EE Chat App

A privacy-first, real-time chat application where the server **never sees your messages**. All encryption and decryption happens on the client using the Web Crypto API.

## Features

- **End-to-End Encryption** — X25519 key exchange + AES-256-GCM message encryption
- **Zero-Knowledge Architecture** — Server stores only encrypted blobs; even admins can't read messages
- **Message Signatures** — Ed25519 signatures on every message (forgery detection)
- **Forward Secrecy** — X3DH-style one-time prekeys so past messages stay safe even if keys leak
- **Real-Time Messaging** — Socket.IO WebSocket with room-based broadcasting
- **Friend System** — Friend requests, block/unblock, online presence
- **Group Chats** — Multi-member chats with admin roles
- **Self-Destructing Messages** — TTL-based message expiration

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Vanilla JS, Web Crypto API, Socket.IO client |
| Backend | TypeScript, Express, Socket.IO |
| Database | PostgreSQL (Supabase) with Row-Level Security |
| Auth | Supabase JWT |
| Hosting | Vercel (frontend) · Render (backend) |

## Encryption Model

```
Signup:  X25519 keypair + Ed25519 signing key → encrypted with AES-GCM (master key from Argon2id) → uploaded
Chat:    X25519 shared secret + HKDF-SHA-256 → per-chat AES-256-GCM key (derived locally, never shared)
Message: Sign with Ed25519 → AES-256-GCM encrypt → ciphertext stored on server
Prekeys: 10 one-time X25519 keys uploaded at signup → consumed per new chat (forward secrecy)
```

No plaintext ever leaves the browser.

## Running Locally

**Backend**
```bash
cd backend
npm install
cp .env.example .env   # fill in Supabase credentials
npm run dev            # starts on port 3000
```

**Frontend**
```bash
cd frontend
npm install
npm start              # serves on port 5173
```

Open `http://localhost:5173`

## Environment Variables

```env
SUPABASE_URL=
SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=
PORT=3000
NODE_ENV=development
```

## Project Structure

```
backend/
  src/
    routes/      # REST API endpoints
    models/      # Supabase DB models (keys, prekeys, messages, etc.)
    socket/      # Socket.IO event handlers
    middleware/  # Auth, validation, rate limiting
    utils/       # Logger, encryption helpers
frontend/
  index.html
  app.js         # Main application logic
  crypto-helper.js  # Web Crypto API wrapper (X25519, Ed25519, AES-GCM, Argon2id)
  config.js      # Backend URL configuration
```

## Security Highlights

- X25519 for key agreement (constant-time, no NIST trust issues)
- Ed25519 message signatures (proves sender authenticity, detects tampering)
- X3DH-style one-time prekeys for forward secrecy
- HKDF-SHA-256 derives a unique AES key per chat from the shared secret
- AES-256-GCM provides authenticated encryption (confidentiality + integrity)
- Argon2id (64 MiB, 3 iterations) for password → master key derivation (GPU-resistant)
- Device identity keys sign public key uploads (MITM protection)
- Row-Level Security (RLS) enforced at the database level
- Helmet.js security headers, Joi input validation, rate limiting

See [CRYPTO_EVOLUTION.md](CRYPTO_EVOLUTION.md) for the full history of algorithm changes and a WhatsApp security comparison.

## License

MIT
