// Crypto Helper — Zero-Knowledge E2EE
// Encryption stack:
//   Key Agreement : X25519 (Web Crypto Level 2)
//   Signatures    : Ed25519
//   Key Derivation: HKDF-SHA-256
//   Password KDF  : Argon2id (argon2-browser WASM)
//   Encryption    : AES-256-GCM  (96-bit random IV per message)
// Forward secrecy: Ephemeral one-time prekeys (X3DH-style)
// Device security: Per-device Ed25519 identity keys

// Argon2id parameters (interactive login profile)
const ARGON2_MEM  = 65536;  // 64 MiB
const ARGON2_TIME = 3;      // 3 iterations
const ARGON2_PARA = 1;
const ARGON2_LEN  = 32;     // 32-byte output → AES-256 key material

// Capture native Web Crypto before any library can shadow it
const _crypto = window.crypto;
const _subtle = _crypto.subtle;

class CryptoHelper {
    constructor() {
        // X25519 long-term identity keys (key agreement)
        this.privateKey = null;
        this.publicKey  = null;
        // Ed25519 long-term identity keys (signing / authenticity)
        this.signingKey = null;
        this.verifyKey  = null;
        // Per-device Ed25519 identity key (device onboarding MITM prevention)
        this.deviceSigningKey       = null;
        this.deviceVerifyKey        = null;
        // AES-256-GCM per-chat session keys
        this.chatKeys = new Map(); // chatId → CryptoKey
    }

    // ============ INDEXEDDB HELPERS ============

    _openDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('EncryptionDB', 2);
            request.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('keys')) {
                    db.createObjectStore('keys');
                }
            };
            request.onsuccess = (e) => resolve(e.target.result);
            request.onerror = () => reject(request.error);
        });
    }

    async _idbSet(key, value) {
        const db = await this._openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(['keys'], 'readwrite');
            tx.objectStore('keys').put(value, key);
            tx.oncomplete = () => { db.close(); resolve(); };
            tx.onerror = () => { db.close(); reject(tx.error); };
        });
    }

    async _idbGet(key) {
        const db = await this._openDB();
        return new Promise((resolve) => {
            const tx = db.transaction(['keys'], 'readonly');
            const req = tx.objectStore('keys').get(key);
            req.onsuccess = () => { db.close(); resolve(req.result ?? null); };
            req.onerror = () => { db.close(); resolve(null); };
        });
    }

    async _idbDelete(key) {
        const db = await this._openDB();
        return new Promise((resolve) => {
            const tx = db.transaction(['keys'], 'readwrite');
            tx.objectStore('keys').delete(key);
            tx.oncomplete = () => { db.close(); resolve(); };
            tx.onerror    = () => { db.close(); resolve(); };
        });
    }

    // ============ X25519 IDENTITY KEYS (key agreement) ============

    async generateUserKeys() {
        console.log('🔐 Generating X25519 identity keypair...');
        const kp = await _subtle.generateKey(
            { name: 'X25519' },
            true,
            ['deriveBits']
        );
        this.privateKey = kp.privateKey;
        this.publicKey  = kp.publicKey;
        console.log('✅ X25519 keypair generated');
        return kp;
    }

    async exportPublicKey() {
        // Export as raw 32-byte X25519 point, base64-encoded
        const raw = await _subtle.exportKey('raw', this.publicKey);
        return btoa(String.fromCharCode(...new Uint8Array(raw)));
    }

    async importPublicKey(base64) {
        const raw = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
        return _subtle.importKey('raw', raw, { name: 'X25519' }, true, []);
    }

    // ============ ED25519 IDENTITY KEYS (signatures) ============

    async generateSigningKeys() {
        console.log('✍️ Generating Ed25519 signing keypair...');
        const kp = await _subtle.generateKey(
            { name: 'Ed25519' },
            true,
            ['sign', 'verify']
        );
        this.signingKey = kp.privateKey;
        this.verifyKey  = kp.publicKey;
        console.log('✅ Ed25519 signing keypair generated');
        return kp;
    }

    async exportSigningPublicKey() {
        const raw = await _subtle.exportKey('raw', this.verifyKey);
        return btoa(String.fromCharCode(...new Uint8Array(raw)));
    }

    async importSigningPublicKey(base64) {
        const raw = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
        return _subtle.importKey('raw', raw, { name: 'Ed25519' }, true, ['verify']);
    }

    // Sign arbitrary bytes/string; returns base64 signature
    async signData(data, key) {
        const signingKey = key || this.signingKey;
        if (!signingKey) throw new Error('No signing key loaded');
        const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        const sig = await _subtle.sign({ name: 'Ed25519' }, signingKey, bytes);
        return btoa(String.fromCharCode(...new Uint8Array(sig)));
    }

    // Verify base64 signature against raw/string data with an imported verify key
    async verifySignature(data, signatureBase64, verifyKey) {
        try {
            const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
            const sig   = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));
            return await _subtle.verify({ name: 'Ed25519' }, verifyKey, sig, bytes);
        } catch {
            return false;
        }
    }

    // Encrypt Ed25519 signing private key with master key
    async encryptSigningKey(signingKey, masterKey) {
        const pkcs8 = await _subtle.exportKey('pkcs8', signingKey);
        const iv = _crypto.getRandomValues(new Uint8Array(12));
        const enc = await _subtle.encrypt({ name: 'AES-GCM', iv }, masterKey, pkcs8);
        return {
            encrypted: btoa(String.fromCharCode(...new Uint8Array(enc))),
            iv: btoa(String.fromCharCode(...new Uint8Array(iv)))
        };
    }

    // Decrypt Ed25519 signing private key
    async decryptSigningKey(encryptedData, masterKey) {
        const iv  = Uint8Array.from(atob(encryptedData.iv),        c => c.charCodeAt(0));
        const enc = Uint8Array.from(atob(encryptedData.encrypted), c => c.charCodeAt(0));
        const dec = await _subtle.decrypt({ name: 'AES-GCM', iv }, masterKey, enc);
        return _subtle.importKey('pkcs8', dec, { name: 'Ed25519' }, true, ['sign']);
    }

    // ============ X25519 KEY AGREEMENT (session key derivation) ============

    // Derive per-chat AES-256-GCM key from static identity keys (existing sessions)
    async deriveChatKey(recipientPublicKey, chatId) {
        console.log(`🔑 Deriving X25519 chat key for chat ${chatId}...`);
        const sharedBits = await _subtle.deriveBits(
            { name: 'X25519', public: recipientPublicKey },
            this.privateKey,
            256
        );
        return this._hkdfToChatKey(sharedBits, chatId, 'static-chat-key-v2');
    }

    // Derive session key AS INITIATOR: ephemeral private key + recipient's one-time prekey public
    // Forward secret: ephemeral private is discarded after this call
    async deriveSessionKeyAsInitiator(myEphPrivate, recipientPrekeyPublic, chatId) {
        console.log(`🔑 Deriving forward-secret session key (initiator) for chat ${chatId}...`);
        const sharedBits = await _subtle.deriveBits(
            { name: 'X25519', public: recipientPrekeyPublic },
            myEphPrivate,
            256
        );
        return this._hkdfToChatKey(sharedBits, chatId, 'prekey-session-v1');
    }

    // Derive session key AS RESPONDER: own prekey private + initiator's ephemeral public
    async deriveSessionKeyAsResponder(myPrekeyPrivate, initiatorEphPublic, chatId) {
        console.log(`🔑 Deriving forward-secret session key (responder) for chat ${chatId}...`);
        const sharedBits = await _subtle.deriveBits(
            { name: 'X25519', public: initiatorEphPublic },
            myPrekeyPrivate,
            256
        );
        return this._hkdfToChatKey(sharedBits, chatId, 'prekey-session-v1');
    }

    // Internal: HKDF(sharedBits, salt=chatId, info) → AES-256-GCM; cached in memory + localStorage
    async _hkdfToChatKey(sharedBits, chatId, info) {
        const hkdfKey = await _subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
        const chatKey = await _subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new TextEncoder().encode(chatId),
                info: new TextEncoder().encode(info),
            },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        this.chatKeys.set(chatId, chatKey);
        const raw = await _subtle.exportKey('raw', chatKey);
        localStorage.setItem(`chatKey_${chatId}`,
            btoa(String.fromCharCode(...new Uint8Array(raw))));
        return chatKey;
    }

    async loadChatKey(chatId) {
        if (this.chatKeys.has(chatId)) return this.chatKeys.get(chatId);
        const stored = localStorage.getItem(`chatKey_${chatId}`);
        if (!stored) return null;
        const raw = Uint8Array.from(atob(stored), c => c.charCodeAt(0));
        const chatKey = await _subtle.importKey(
            'raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']
        );
        this.chatKeys.set(chatId, chatKey);
        return chatKey;
    }

    // ============ ONE-TIME PREKEYS (forward secrecy) ============

    // Generate `count` X25519 prekey pairs + Ed25519 signatures over each public key
    async generatePrekeys(count = 10) {
        if (!this.signingKey) throw new Error('Signing key not loaded — cannot sign prekeys');
        const prekeys = [];
        for (let i = 0; i < count; i++) {
            const kp = await _subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
            const pubRaw    = new Uint8Array(await _subtle.exportKey('raw', kp.publicKey));
            const privPkcs8 = new Uint8Array(await _subtle.exportKey('pkcs8', kp.privateKey));
            const pubBase64 = btoa(String.fromCharCode(...pubRaw));
            // Sign the prekey public key with user's Ed25519 identity key
            const signature = await this.signData(pubRaw);
            prekeys.push({
                public_key:   pubBase64,
                signature,
                _privateBytes: Array.from(privPkcs8), // local only, never sent to server
            });
        }
        return prekeys;
    }

    // Encrypt and store full prekey bundle (including private keys) in IndexedDB
    async storePrekeyBundle(prekeys, masterKey) {
        const payload = JSON.stringify(prekeys.map(p => ({
            public_key:  p.public_key,
            signature:   p.signature,
            priv_bytes:  p._privateBytes,
        })));
        const iv  = _crypto.getRandomValues(new Uint8Array(12));
        const enc = await _subtle.encrypt(
            { name: 'AES-GCM', iv }, masterKey, new TextEncoder().encode(payload)
        );
        await this._idbSet('prekeyBundle', JSON.stringify({
            encrypted: btoa(String.fromCharCode(...new Uint8Array(enc))),
            iv:        btoa(String.fromCharCode(...new Uint8Array(iv))),
        }));
    }

    async loadPrekeyBundle(masterKey) {
        const stored = await this._idbGet('prekeyBundle');
        if (!stored) return [];
        const { encrypted, iv } = JSON.parse(stored);
        const encBytes = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
        const ivBytes  = Uint8Array.from(atob(iv),        c => c.charCodeAt(0));
        const dec = await _subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, masterKey, encBytes);
        return JSON.parse(new TextDecoder().decode(dec));
    }

    // Retrieve and delete one prekey private key by its public key (base64); returns X25519 CryptoKey
    // Deletion is the "one-time" guarantee: private key is gone after consumption → forward secrecy
    async consumePrekey(prekeyPublicBase64, masterKey) {
        const bundle = await this.loadPrekeyBundle(masterKey);
        const idx = bundle.findIndex(p => p.public_key === prekeyPublicBase64);
        if (idx === -1) throw new Error('Prekey not found in local bundle');
        const prekey = bundle.splice(idx, 1)[0];
        await this.storePrekeyBundle(bundle, masterKey); // save bundle without consumed key
        const privBytes = new Uint8Array(prekey.priv_bytes);
        return _subtle.importKey('pkcs8', privBytes, { name: 'X25519' }, false, ['deriveBits']);
    }

    // Return only the server-safe portion of prekeys (public key + signature, no private)
    prekeyServerPayload(prekeys) {
        return prekeys.map(p => ({ public_key: p.public_key, signature: p.signature }));
    }

    // ============ DEVICE IDENTITY KEYS ============

    async generateDeviceIdentityKey() {
        console.log('📱 Generating device Ed25519 identity keypair...');
        const kp = await _subtle.generateKey(
            { name: 'Ed25519' }, true, ['sign', 'verify']
        );
        this.deviceSigningKey = kp.privateKey;
        this.deviceVerifyKey  = kp.publicKey;
        return kp;
    }

    async exportDevicePublicKey() {
        const raw = await _subtle.exportKey('raw', this.deviceVerifyKey);
        return btoa(String.fromCharCode(...new Uint8Array(raw)));
    }

    // Store device identity key encrypted with master key
    async storeDeviceIdentityKey(masterKey) {
        const pkcs8 = await _subtle.exportKey('pkcs8', this.deviceSigningKey);
        const iv = _crypto.getRandomValues(new Uint8Array(12));
        const enc = await _subtle.encrypt({ name: 'AES-GCM', iv }, masterKey, pkcs8);
        await this._idbSet('deviceIdentityKey', JSON.stringify({
            encrypted: btoa(String.fromCharCode(...new Uint8Array(enc))),
            iv:        btoa(String.fromCharCode(...new Uint8Array(iv))),
            pub:       await this.exportDevicePublicKey(),
        }));
    }

    async loadDeviceIdentityKey(masterKey) {
        const stored = await this._idbGet('deviceIdentityKey');
        if (!stored) return false;
        const { encrypted, iv, pub } = JSON.parse(stored);
        const enc     = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
        const ivBytes = Uint8Array.from(atob(iv),        c => c.charCodeAt(0));
        const dec = await _subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, masterKey, enc);
        this.deviceSigningKey = await _subtle.importKey(
            'pkcs8', dec, { name: 'Ed25519' }, true, ['sign']
        );
        const pubRaw = Uint8Array.from(atob(pub), c => c.charCodeAt(0));
        this.deviceVerifyKey = await _subtle.importKey(
            'raw', pubRaw, { name: 'Ed25519' }, true, ['verify']
        );
        return true;
    }

    // Sign the user's X25519 public key with this device's identity signing key
    // Proves the device is legitimate and not performing MITM during onboarding
    async signUserPublicKeyWithDevice(x25519PubBase64) {
        if (!this.deviceSigningKey) throw new Error('Device identity key not loaded');
        return this.signData(x25519PubBase64, this.deviceSigningKey);
    }

    // ============ MESSAGE ENCRYPTION / SIGNING ============

    async encryptMessage(message, chatId) {
        const chatKey = await this.loadChatKey(chatId);
        if (!chatKey) throw new Error('No chat key for this conversation');
        const iv  = _crypto.getRandomValues(new Uint8Array(12)); // 96-bit random IV per message
        const enc = await _subtle.encrypt(
            { name: 'AES-GCM', iv },
            chatKey,
            new TextEncoder().encode(message)
        );
        return {
            encrypted: btoa(String.fromCharCode(...new Uint8Array(enc))),
            iv:        btoa(String.fromCharCode(...new Uint8Array(iv))),
        };
    }

    async decryptMessage(encryptedBase64, ivBase64, chatId) {
        const chatKey = await this.loadChatKey(chatId);
        if (!chatKey) throw new Error('No chat key for this conversation');
        const enc = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
        const iv  = Uint8Array.from(atob(ivBase64),        c => c.charCodeAt(0));
        const dec = await _subtle.decrypt({ name: 'AES-GCM', iv }, chatKey, enc);
        return new TextDecoder().decode(dec);
    }

    // Sign plaintext before encryption (sign-then-encrypt for authenticity)
    async signMessage(plaintext) {
        return this.signData(plaintext);
    }

    // Verify a received message's signature using the sender's signing public key (base64 raw)
    async verifyMessage(plaintext, signatureBase64, senderSigningPublicKeyBase64) {
        const verifyKey = await this.importSigningPublicKey(senderSigningPublicKeyBase64);
        return this.verifySignature(plaintext, signatureBase64, verifyKey);
    }

    // ============ PRIVATE KEY ENCRYPTION (AES-GCM with master key) ============

    async encryptPrivateKey(privateKey, masterKey) {
        const pkcs8 = await _subtle.exportKey('pkcs8', privateKey);
        const iv = _crypto.getRandomValues(new Uint8Array(12));
        const enc = await _subtle.encrypt({ name: 'AES-GCM', iv }, masterKey, pkcs8);
        return {
            encrypted: btoa(String.fromCharCode(...new Uint8Array(enc))),
            iv:        btoa(String.fromCharCode(...new Uint8Array(iv)))
        };
    }

    async decryptPrivateKey(encryptedData, masterKey) {
        const iv  = Uint8Array.from(atob(encryptedData.iv),        c => c.charCodeAt(0));
        const enc = Uint8Array.from(atob(encryptedData.encrypted), c => c.charCodeAt(0));
        const dec = await _subtle.decrypt({ name: 'AES-GCM', iv }, masterKey, enc);
        return _subtle.importKey('pkcs8', dec, { name: 'X25519' }, true, ['deriveBits']);
    }

    // ============ MASTER KEY — Argon2id path ============

    async generateMasterKey() {
        return _subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    }

    // Encrypt master key using Argon2id-derived wrapping key (random salt stored alongside)
    async encryptMasterKeyWithPassword(masterKey, password) {
        if (typeof argon2 === 'undefined') throw new Error('argon2-browser library not loaded');
        const salt = _crypto.getRandomValues(new Uint8Array(16));
        const result = await argon2.hash({
            pass: password, salt,
            type: argon2.ArgonType.Argon2id,
            mem: ARGON2_MEM, time: ARGON2_TIME, parallelism: ARGON2_PARA, hashLen: ARGON2_LEN,
        });
        const wrappingKey = await _subtle.importKey(
            'raw', result.hash, { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']
        );
        const iv = _crypto.getRandomValues(new Uint8Array(12));
        const wrapped = await _subtle.wrapKey('raw', masterKey, wrappingKey, { name: 'AES-GCM', iv });
        return {
            wrapped: btoa(String.fromCharCode(...new Uint8Array(wrapped))),
            iv:      btoa(String.fromCharCode(...new Uint8Array(iv))),
            salt:    btoa(String.fromCharCode(...salt)),
            kdf:     'argon2id',
        };
    }

    // Decrypt master key using Argon2id
    async decryptMasterKeyWithPassword(encryptedData, password) {
        if (typeof argon2 === 'undefined') throw new Error('argon2-browser library not loaded');
        const salt    = Uint8Array.from(atob(encryptedData.salt),    c => c.charCodeAt(0));
        const iv      = Uint8Array.from(atob(encryptedData.iv),      c => c.charCodeAt(0));
        const wrapped = Uint8Array.from(atob(encryptedData.wrapped), c => c.charCodeAt(0));
        const result = await argon2.hash({
            pass: password, salt,
            type: argon2.ArgonType.Argon2id,
            mem: ARGON2_MEM, time: ARGON2_TIME, parallelism: ARGON2_PARA, hashLen: ARGON2_LEN,
        });
        const wrappingKey = await _subtle.importKey(
            'raw', result.hash, { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']
        );
        return _subtle.unwrapKey(
            'raw', wrapped, wrappingKey,
            { name: 'AES-GCM', iv },
            { name: 'AES-GCM', length: 256 },
            true, ['encrypt', 'decrypt']
        );
    }

    // Argon2id-derived auth password for Supabase (deterministic: fixed salt from email)
    async deriveAuthPassword(password, email) {
        if (typeof argon2 === 'undefined') throw new Error('argon2-browser library not loaded');
        const saltHash = await _subtle.digest(
            'SHA-256', new TextEncoder().encode(email.toLowerCase() + ':auth-salt-v2')
        );
        const result = await argon2.hash({
            pass: password,
            salt: new Uint8Array(saltHash).slice(0, 16),
            type: argon2.ArgonType.Argon2id,
            mem: ARGON2_MEM, time: ARGON2_TIME, parallelism: ARGON2_PARA, hashLen: ARGON2_LEN,
        });
        return btoa(String.fromCharCode(...result.hash));
    }

    // ============ MASTER KEY STORAGE ============

    async storeMasterKeyInIndexedDB(masterKey) {
        const raw = await _subtle.exportKey('raw', masterKey);
        await this._idbSet('masterKey', btoa(String.fromCharCode(...new Uint8Array(raw))));
        console.log('✅ Master key stored in IndexedDB');
    }

    async loadMasterKeyFromIndexedDB() {
        try {
            const stored = await this._idbGet('masterKey');
            if (!stored) return null;
            const raw = Uint8Array.from(atob(stored), c => c.charCodeAt(0));
            return _subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        } catch {
            return null;
        }
    }

    async clearMasterKeyFromIndexedDB() {
        await this._idbDelete('masterKey');
        console.log('🗑️ Cleared master key from IndexedDB');
    }

    async clearMasterKey() { await this.clearMasterKeyFromIndexedDB(); }

    // ============ RECOVERY KEY ============

    async generateRecoveryKey(masterKey) {
        const raw  = await _subtle.exportKey('raw', masterKey);
        const salt = _crypto.getRandomValues(new Uint8Array(16));
        const combined = new Uint8Array(48);
        combined.set(new Uint8Array(raw), 0);
        combined.set(salt, 32);
        return btoa(String.fromCharCode(...combined)).match(/.{1,4}/g).join('-');
    }

    async restoreMasterKeyFromRecovery(recoveryKey) {
        const combined = Uint8Array.from(atob(recoveryKey.replace(/-/g, '')), c => c.charCodeAt(0));
        return _subtle.importKey(
            'raw', combined.slice(0, 32), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );
    }

    // ============ SERVER KEYS CACHE ============

    async storeCachedServerKeys(keys) {
        await this._idbSet('cachedServerKeys', JSON.stringify(keys));
    }

    async loadCachedServerKeys() {
        try {
            const stored = await this._idbGet('cachedServerKeys');
            return stored ? JSON.parse(stored) : null;
        } catch {
            return null;
        }
    }

    async clearCachedServerKeys() {
        await this._idbDelete('cachedServerKeys');
    }

    // ============ FULL KEY CLEAR (logout) ============

    clearKeys() {
        this.privateKey       = null;
        this.publicKey        = null;
        this.signingKey       = null;
        this.verifyKey        = null;
        this.deviceSigningKey = null;
        this.deviceVerifyKey  = null;
        this.chatKeys.clear();
        Object.keys(localStorage).forEach(k => {
            if (k.startsWith('chatKey_')) localStorage.removeItem(k);
        });
        console.log('🗑️ All in-memory keys cleared');
    }
}

window.CryptoHelper = CryptoHelper;
