// Crypto Helper Functions for Zero-Knowledge Encryption

class CryptoHelper {
    constructor() {
        this.privateKey = null;
        this.publicKey = null;
        this.chatKeys = new Map(); // chatId -> AES key
    }

    // ============ INDEXEDDB HELPERS ============

    _openDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('EncryptionDB', 1);
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
            tx.onerror = () => { db.close(); resolve(); };
        });
    }

    /**
     * Generate ECDH key pair for user (P-256)
     */
    async generateUserKeys() {
        console.log('🔐 Generating ECDH key pair (P-256)...');

        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDH',
                namedCurve: 'P-256',
            },
            true,
            ['deriveKey', 'deriveBits']
        );

        this.privateKey = keyPair.privateKey;
        this.publicKey = keyPair.publicKey;

        console.log('✅ ECDH key pair generated!');
        console.log('🔒 Private key will be encrypted before upload (NEVER stored plaintext!)');

        return keyPair;
    }

    /**
     * Load private key from localStorage
     */
    async loadPrivateKey() {
        const stored = localStorage.getItem('privateKey');
        if (!stored) return null;

        const keyData = JSON.parse(stored);
        this.privateKey = await crypto.subtle.importKey(
            'jwk',
            keyData,
            {
                name: 'ECDH',
                namedCurve: 'P-256',
            },
            true,
            ['deriveKey', 'deriveBits']
        );

        console.log('✅ Private key loaded from storage');
        return this.privateKey;
    }

    /**
     * Export public key as base64 string
     */
    async exportPublicKey() {
        const exported = await crypto.subtle.exportKey('jwk', this.publicKey);
        return btoa(JSON.stringify(exported));
    }

    /**
     * Import ECDH public key from base64 string
     */
    async importPublicKey(base64Key) {
        const keyData = JSON.parse(atob(base64Key));
        return await crypto.subtle.importKey(
            'jwk',
            keyData,
            {
                name: 'ECDH',
                namedCurve: 'P-256',
            },
            true,
            []
        );
    }

    /**
     * Derive a per-chat AES-256 key using ECDH + HKDF.
     * Both parties independently derive the same key:
     *   derivedKey = HKDF(ECDH(myPrivate, theirPublic), salt=chatId)
     */
    async deriveChatKey(recipientPublicKey, chatId) {
        console.log(`🔑 Deriving ECDH chat key for chat ${chatId}...`);

        // Step 1: ECDH - compute shared secret
        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: recipientPublicKey },
            this.privateKey,
            256
        );

        // Step 2: HKDF - derive a unique AES-256 key for this specific chat
        const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
        const chatKey = await crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new TextEncoder().encode(chatId),
                info: new TextEncoder().encode('chat-key-v1'),
            },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        this.chatKeys.set(chatId, chatKey);
        const exported = await crypto.subtle.exportKey('raw', chatKey);
        localStorage.setItem(
            `chatKey_${chatId}`,
            btoa(String.fromCharCode(...new Uint8Array(exported)))
        );

        console.log(`✅ ECDH chat key derived for chat ${chatId}`);
        return chatKey;
    }

    /**
     * Load chat key from storage
     */
    async loadChatKey(chatId) {
        // Check memory first
        if (this.chatKeys.has(chatId)) {
            return this.chatKeys.get(chatId);
        }

        // Load from storage
        const stored = localStorage.getItem(`chatKey_${chatId}`);
        if (!stored) return null;

        const rawKey = Uint8Array.from(atob(stored), c => c.charCodeAt(0));
        const chatKey = await crypto.subtle.importKey(
            'raw',
            rawKey,
            {
                name: 'AES-GCM',
            },
            true,
            ['encrypt', 'decrypt']
        );

        this.chatKeys.set(chatId, chatKey);
        console.log(`✅ Chat key loaded for chat ${chatId}`);
        return chatKey;
    }



    /**
     * Encrypt a message
     */
    async encryptMessage(message, chatId) {
        const chatKey = await this.loadChatKey(chatId);
        if (!chatKey) {
            throw new Error('No chat key found for this chat');
        }

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encodedMessage = new TextEncoder().encode(message);

        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
            },
            chatKey,
            encodedMessage
        );

        return {
            encrypted: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
            iv: btoa(String.fromCharCode(...new Uint8Array(iv))),
        };
    }

    /**
     * Decrypt a message
     */
    async decryptMessage(encryptedBase64, ivBase64, chatId) {
        const chatKey = await this.loadChatKey(chatId);
        if (!chatKey) {
            throw new Error('No chat key found for this chat');
        }

        const encrypted = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
        const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));

        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
            },
            chatKey,
            encrypted
        );

        return new TextDecoder().decode(decrypted);
    }

    /**
     * Clear all keys (logout)
     */
    clearKeys() {
        this.privateKey = null;
        this.publicKey = null;
        this.chatKeys.clear();
        
        // Clear from storage
        Object.keys(localStorage).forEach(key => {
            if (key.startsWith('chatKey_') || key === 'privateKey') {
                localStorage.removeItem(key);
            }
        });

        console.log('🗑️ All keys cleared');
    }

    // ============ MASTER KEY METHODS ============

    /**
     * Generate master encryption key (random, independent of password)
     */
    async generateMasterKey() {
        const masterKey = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        return masterKey;
    }

    /**
     * Encrypt master key with password
     */
    async encryptMasterKeyWithPassword(masterKey, password, email) {
        const encoder = new TextEncoder();
        const salt = await crypto.subtle.digest('SHA-256', encoder.encode(email));
        
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        const wrappingKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: new Uint8Array(salt),
                iterations: 100000,
                hash: 'SHA-256'
            },
            passwordKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['wrapKey', 'unwrapKey']
        );

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const wrapped = await crypto.subtle.wrapKey('raw', masterKey, wrappingKey, { name: 'AES-GCM', iv });

        return {
            wrapped: btoa(String.fromCharCode(...new Uint8Array(wrapped))),
            iv: btoa(String.fromCharCode(...new Uint8Array(iv))),
            salt: btoa(String.fromCharCode(...new Uint8Array(salt)))
        };
    }

    /**
     * Decrypt master key with password
     */
    async decryptMasterKeyWithPassword(encryptedData, password) {
        const encoder = new TextEncoder();
        const salt = Uint8Array.from(atob(encryptedData.salt), c => c.charCodeAt(0));
        const iv = Uint8Array.from(atob(encryptedData.iv), c => c.charCodeAt(0));
        const wrapped = Uint8Array.from(atob(encryptedData.wrapped), c => c.charCodeAt(0));

        const passwordKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        const wrappingKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            passwordKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['wrapKey', 'unwrapKey']
        );

        const masterKey = await crypto.subtle.unwrapKey(
            'raw',
            wrapped,
            wrappingKey,
            { name: 'AES-GCM', iv },
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        return masterKey;
    }

    /**
     * Derive auth password from user password
     */
    async deriveAuthPassword(password, email) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password + ':auth:' + email);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return btoa(String.fromCharCode(...new Uint8Array(hash)));
    }

    /**
     * Store master key in IndexedDB
     */
    async storeMasterKeyInIndexedDB(masterKey) {
        const exported = await crypto.subtle.exportKey('raw', masterKey);
        const base64Key = btoa(String.fromCharCode(...new Uint8Array(exported)));
        await this._idbSet('masterKey', base64Key);
        console.log('✅ Master key stored in IndexedDB');
    }

    /**
     * Load master key from IndexedDB
     */
    async loadMasterKeyFromIndexedDB() {
        try {
            const stored = await this._idbGet('masterKey');
            if (!stored) return null;
            const keyData = Uint8Array.from(atob(stored), c => c.charCodeAt(0));
            return await crypto.subtle.importKey(
                'raw',
                keyData,
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );
        } catch (error) {
            console.error('Failed to load master key:', error);
            return null;
        }
    }

    /**
     * Clear master key from IndexedDB
     */
    async clearMasterKeyFromIndexedDB() {
        await this._idbDelete('masterKey');
        console.log('🗑️ Cleared master key from IndexedDB');
    }

    /**
     * Encrypt ECDH private key with master key (AES-GCM wrap)
     */
    async encryptPrivateKey(privateKey, masterKey) {
        const exported = await crypto.subtle.exportKey('pkcs8', privateKey);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            masterKey,
            exported
        );

        return {
            encrypted: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
            iv: btoa(String.fromCharCode(...new Uint8Array(iv)))
        };
    }

    /**
     * Decrypt ECDH private key with master key
     */
    async decryptPrivateKey(encryptedData, masterKey) {
        const iv = Uint8Array.from(atob(encryptedData.iv), c => c.charCodeAt(0));
        const encrypted = Uint8Array.from(atob(encryptedData.encrypted), c => c.charCodeAt(0));

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            masterKey,
            encrypted
        );

        return await crypto.subtle.importKey(
            'pkcs8',
            decrypted,
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );
    }

    /**
     * Generate recovery key for account recovery
     */
    async generateRecoveryKey(masterKey) {
        // Export master key
        const exported = await crypto.subtle.exportKey('raw', masterKey);
        
        // Generate random salt
        const salt = crypto.getRandomValues(new Uint8Array(16));
        
        // Combine and encode
        const combined = new Uint8Array(exported.byteLength + salt.byteLength);
        combined.set(new Uint8Array(exported), 0);
        combined.set(salt, exported.byteLength);
        
        // Convert to base32-like format (easier to write down)
        const base64 = btoa(String.fromCharCode(...combined));
        
        // Format as groups of 4 characters
        const formatted = base64.match(/.{1,4}/g).join('-');
        
        return formatted;
    }

    /**
     * Restore master key from recovery key
     */
    async restoreMasterKeyFromRecovery(recoveryKey) {
        try {
            // Remove dashes and decode
            const base64 = recoveryKey.replace(/-/g, '');
            const combined = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
            
            // Extract master key (first 32 bytes for AES-256)
            const masterKeyData = combined.slice(0, 32);
            
            // Import as master key
            const masterKey = await crypto.subtle.importKey(
                'raw',
                masterKeyData,
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );
            
            return masterKey;
        } catch (error) {
            console.error('Failed to restore from recovery key:', error);
            throw new Error('Invalid recovery key');
        }
    }

    /**
     * Clear master key from IndexedDB (for corrupted accounts)
     */
    async clearMasterKey() {
        await this.clearMasterKeyFromIndexedDB();
    }

    // ============ SERVER KEYS CACHE ============

    /**
     * Cache the server's encrypted key bundle locally.
     * This eliminates a network round-trip on every page reload / session restore.
     * Security: the bundle only contains already-encrypted blobs; the master key
     * needed to decrypt them is stored separately and is equally protected.
     */
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
}

// Export for use in app.js
window.CryptoHelper = CryptoHelper;
