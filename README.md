# SecureChat — Zero-Knowledge E2EE Chat App

A privacy-first, real-time chat application where the server **never sees your messages**. All encryption and decryption happens on the client using the Web Crypto API.

## Features

- **End-to-End Encryption** — ECDH P-256 key exchange + AES-256-GCM message encryption
- **Zero-Knowledge Architecture** — Server stores only encrypted blobs; even admins can't read messages
- **Real-Time Messaging** — Socket.IO WebSocket with room-based broadcasting
- **Friend System** — Friend requests, block/unblock, online presence
- **Group Chats** — Multi-member chats with admin roles
- **Self-Destructing Messages** — TTL-based message expiration
- **Multi-Device Support** — Encrypted key sync across devices

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
Signup:  ECDH P-256 keypair → private key encrypted with AES-GCM (master key) → uploaded to server
Chat:    ECDH shared secret + HKDF-SHA-256 → per-chat AES-256-GCM key (derived locally, never shared)
Message: AES-256-GCM encrypt → ciphertext stored on server
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
    models/      # Supabase DB models
    socket/      # Socket.IO event handlers
    middleware/  # Auth, validation, rate limiting
    utils/       # Logger, encryption helpers
frontend/
  index.html
  app.js         # Main application logic
  crypto-helper.js  # Web Crypto API wrapper (ECDH, AES-GCM)
  config.js      # Backend URL configuration
```

## Security Highlights

- ECDH P-256 for key agreement (replaces RSA — faster, smaller keys, same security level)
- HKDF-SHA-256 derives a unique AES key per chat from the ECDH shared secret
- AES-256-GCM provides authenticated encryption (confidentiality + integrity)
- Master key derived from password via PBKDF2 (100k iterations) encrypts the ECDH private key
- Row-Level Security (RLS) enforced at the database level
- Helmet.js security headers, Joi input validation, rate limiting

## License

MIT
