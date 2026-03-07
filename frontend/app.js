// Main Application Logic

const BACKEND_URL = window.APP_CONFIG?.BACKEND_URL || 'http://localhost:3000';
const SUPABASE_URL = window.APP_CONFIG?.SUPABASE_URL || 'https://ethxvptzasiezviuvfwv.supabase.co';
const SUPABASE_ANON_KEY = window.APP_CONFIG?.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV0aHh2cHR6YXNpZXp2aXV2Znd2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjcxOTg3NDIsImV4cCI6MjA4Mjc3NDc0Mn0.XikHP2O24anokFNxPs9Y1CNTbjn4xEnosVMs7KGZOSE';

// Ping backend immediately so Render free-tier wakes up before the user clicks Login
fetch(`${BACKEND_URL}/health`).catch(() => {});

// Initialize Supabase client
const supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Initialize Crypto Helper
const cryptoHelper = new CryptoHelper();

// Global state
let currentUser = null;
let socket = null;
let currentChatId = null;
let currentRecipientId = null;

// DOM Elements
const authSection = document.getElementById('authSection');
const chatSection = document.getElementById('chatSection');
const alertContainer = document.getElementById('alertContainer');

// Extended app state
let currentRecipientName = null;
const recentChatsData = new Map(); // chatId -> { name, recipientId, lastMsg, lastTime, unreadCount }
const profileCache    = new Map(); // userId -> profile object

function getDisplayName(profile, id) {
    if (!profile) return (id || '?').substring(0, 8) + '\u2026';
    return profile.display_name || profile.username || profile.email?.split('@')[0] || (id || '?').substring(0, 8);
}
function getInitial(name) { return ((name || '?')[0]).toUpperCase(); }
function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function formatTime(iso) {
    if (!iso) return '';
    const d = new Date(iso), now = new Date(), diffDays = Math.floor((now - d) / 86400000);
    if (diffDays === 0) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7)  return d.toLocaleDateString([], { weekday: 'short' });
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

// Initialize app
document.addEventListener('DOMContentLoaded', async () => {
    const { data: { session } } = await supabaseClient.auth.getSession();
    if (session) await handleExistingSession(session);

    document.getElementById('signupBtn').addEventListener('click', handleSignup);
    document.getElementById('loginBtn').addEventListener('click', handleLogin);
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    document.getElementById('sendBtn').addEventListener('click', sendMessage);
    document.getElementById('messageInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    // User search with 300 ms debounce
    let searchTimer;
    document.getElementById('searchInput').addEventListener('input', (e) => {
        clearTimeout(searchTimer);
        const q = e.target.value.trim();
        if (!q) { document.getElementById('searchResults').classList.remove('open'); return; }
        searchTimer = setTimeout(() => searchUsers(q), 300);
    });
    // Close search dropdown on outside click
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.search-wrap'))
            document.getElementById('searchResults').classList.remove('open');
    });
});

/**
 * Handle existing session
 */
async function handleExistingSession(session) {
    try {
        currentUser = session.user;
        updateDebugLog('🔄 Restoring session...');

        updateDebugLog('🔄 Loading master key from device...');
        const masterKey = await cryptoHelper.loadMasterKeyFromIndexedDB();

        if (!masterKey) {
            updateDebugLog('⚠️ Master key not found on this device');
            authSection.style.display = 'block';
            chatSection.style.display = 'none';
            showAlert('info', 'Please enter your password to decrypt your data on this device.');
            const emailInput = document.getElementById('email');
            if (emailInput && session.user.email) emailInput.value = session.user.email;
            const passwordInput = document.getElementById('password');
            if (passwordInput) passwordInput.focus();
            return;
        }

        updateDebugLog('✅ Master key loaded from IndexedDB');

        const { data: { session: freshSession }, error: sessionError } = await supabaseClient.auth.getSession();
        if (sessionError || !freshSession) {
            updateDebugLog('⚠️ Session expired');
            showAlert('error', 'Session expired. Please login again.');
            await supabaseClient.auth.signOut();
            return;
        }

        updateDebugLog('🔄 Loading encrypted RSA keys...');
        let keys = await cryptoHelper.loadCachedServerKeys();
        if (keys) {
            updateDebugLog('✅ Keys loaded from local cache (no network needed)');
        } else {
            updateDebugLog('🔄 Cache empty — downloading from server...');
            const response = await fetch(`${BACKEND_URL}/api/keys/${freshSession.user.id}`, {
                headers: { 'Authorization': `Bearer ${freshSession.access_token}` },
            });

            if (!response.ok) {
                if (response.status === 404) {
                    updateDebugLog('⚠️ No encryption keys found. Please complete setup.');
                    showAlert('error', 'Account setup incomplete. Please sign up again.');
                    await supabaseClient.auth.signOut();
                    return;
                }
                throw new Error('Failed to fetch encrypted RSA keys');
            }

            keys = await response.json();
            updateDebugLog('✅ RSA keys downloaded');
            await cryptoHelper.storeCachedServerKeys(keys);
        }

        updateDebugLog('🔄 Decrypting RSA private key...');
        try {
            cryptoHelper.privateKey = await cryptoHelper.decryptRSAPrivateKey(keys.encrypted_rsa_private_key, masterKey);
            cryptoHelper.publicKey = await cryptoHelper.importPublicKey(keys.rsa_public_key);
            updateDebugLog('✅ RSA keys decrypted and ready');
        } catch (decryptError) {
            updateDebugLog('❌ Failed to decrypt keys - master key mismatch');
            showAlert('error', 'Encryption key mismatch. This account may be corrupted. Please delete your account and sign up again.');
            await supabaseClient.auth.signOut();
            await cryptoHelper.clearMasterKey();
            await cryptoHelper.clearCachedServerKeys();
            return;
        }

        showAlert('info', 'Session restored! Loading your chats...');
        await initializeChat();
    } catch (error) {
        console.error('Session error:', error);
        updateDebugLog(`❌ Error: ${error.message}`);
        showAlert('error', 'Failed to restore session. Please login again.');
        await supabaseClient.auth.signOut();
    }
}

/**
 * Handle signup
 */
async function handleSignup() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    if (!email || !password) {
        showAlert('error', 'Please fill in all fields');
        return;
    }
    if (password.length < 6) {
        showAlert('error', 'Password must be at least 6 characters');
        return;
    }

    try {
        updateDebugLog('🔄 Step 1: Generating master encryption key...');
        const masterKey = await cryptoHelper.generateMasterKey();
        updateDebugLog('✅ Step 1: Master key generated! (256-bit AES-GCM, random)');

        updateDebugLog('🔄 Step 2: Encrypting master key with password...');
        const encryptedMasterKey = await cryptoHelper.encryptMasterKeyWithPassword(masterKey, password, email);
        updateDebugLog('✅ Step 2: Master key encrypted! (PBKDF2 100k iterations)');

        updateDebugLog('🔄 Step 3: Deriving auth password...');
        const authPassword = await cryptoHelper.deriveAuthPassword(password, email);
        updateDebugLog('✅ Step 3: Auth password derived! (SHA-256)');

        updateDebugLog('🔄 Step 4: Creating Supabase account...');
        const { data, error } = await supabaseClient.auth.signUp({ email, password: authPassword });
        if (error) throw error;

        if (data.user) {
            currentUser = data.user;
            updateDebugLog('✅ Step 4: Account created!');

            updateDebugLog('🔄 Step 5: Creating user profile...');
            const profileResponse = await fetch(`${BACKEND_URL}/api/auth/me`, {
                method: 'GET',
                headers: { 'Authorization': `Bearer ${data.session.access_token}` },
            });
            if (!profileResponse.ok) {
                const errorData = await profileResponse.json();
                throw new Error(`Failed to create user profile: ${errorData.error || profileResponse.statusText}`);
            }
            updateDebugLog('✅ Step 5: Profile created!');

            updateDebugLog('🔄 Step 6: Generating RSA key pair (2048-bit)...');
            await cryptoHelper.generateUserKeys();
            updateDebugLog('✅ Step 6: RSA keys generated!');

            updateDebugLog('🔄 Step 7: Encrypting RSA private key with master key...');
            const encryptedRSAPrivateKey = await cryptoHelper.encryptRSAPrivateKey(cryptoHelper.privateKey, masterKey);
            updateDebugLog('✅ Step 7: RSA private key encrypted! (Double encryption)');

            updateDebugLog('🔄 Step 8: Storing master key on device (IndexedDB)...');
            await cryptoHelper.storeMasterKeyInIndexedDB(masterKey);
            updateDebugLog('✅ Step 8: Master key stored locally! (Fast login next time)');

            updateDebugLog('🔄 Step 9: Uploading encrypted keys to server...');
            const publicKeyBase64 = await cryptoHelper.exportPublicKey();
            const response = await fetch(`${BACKEND_URL}/api/keys`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${data.session.access_token}`,
                },
                body: JSON.stringify({
                    rsa_public_key: publicKeyBase64,
                    encrypted_master_key: encryptedMasterKey,
                    encrypted_rsa_private_key: encryptedRSAPrivateKey,
                }),
            });
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(`Failed to upload keys: ${errorData.error || response.statusText}`);
            }
            updateDebugLog('✅ Step 9: All encrypted keys uploaded!');

            updateDebugLog('🔄 Step 10: Generating account recovery key...');
            const recoveryKey = await cryptoHelper.generateRecoveryKey(masterKey);
            updateDebugLog('✅ Step 10: Recovery key generated!');

            showRecoveryKey(recoveryKey, email);
            updateDebugLog('🎉 Zero-Knowledge setup complete!');
            updateDebugLog('🔒 Your password NEVER leaves this device unencrypted!');
            updateDebugLog('💾 SAVE YOUR RECOVERY KEY - You cannot reset your password without it!');

            showAlert('success', 'Account created! IMPORTANT: Save your recovery key before continuing.');
            await initializeChat();
        }
    } catch (error) {
        console.error('Signup error:', error);
        showAlert('error', error.message);
        updateDebugLog(`❌ Error: ${error.message}`);
    }
}

/**
 * Handle login
 */
async function handleLogin() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    if (!email || !password) {
        showAlert('error', 'Please fill in all fields');
        return;
    }

    try {
        updateDebugLog('🔄 Step 1: Checking for master key on device...');
        let masterKey = await cryptoHelper.loadMasterKeyFromIndexedDB();

        if (masterKey) {
            updateDebugLog('✅ Step 1: Master key found on device! (Fast login)');
        } else {
            updateDebugLog('⚠️ Step 1: Master key not on device (first login on this device)');
        }

        updateDebugLog('🔄 Step 2: Deriving auth password...');
        const authPassword = await cryptoHelper.deriveAuthPassword(password, email);
        updateDebugLog('✅ Step 2: Auth password derived!');

        updateDebugLog('🔄 Step 3: Logging into Supabase...');
        const { data, error } = await supabaseClient.auth.signInWithPassword({ email, password: authPassword });
        if (error) throw error;

        currentUser = data.user;
        updateDebugLog('✅ Step 3: Logged in!');

        if (!masterKey) {
            updateDebugLog('🔄 Step 4: Downloading encrypted master key from server...');
            const response = await fetch(`${BACKEND_URL}/api/keys/${data.user.id}`, {
                headers: { 'Authorization': `Bearer ${data.session.access_token}` },
            });
            if (!response.ok) throw new Error('Failed to fetch encrypted keys from server');

            const keys = await response.json();
            updateDebugLog('✅ Step 4: Encrypted keys downloaded!');

            updateDebugLog('🔄 Step 5: Decrypting master key with password...');
            masterKey = await cryptoHelper.decryptMasterKeyWithPassword(keys.encrypted_master_key, password);
            updateDebugLog('✅ Step 5: Master key decrypted!');

            updateDebugLog('🔄 Step 6: Storing master key on device for next time...');
            await cryptoHelper.storeMasterKeyInIndexedDB(masterKey);
            updateDebugLog('✅ Step 6: Master key stored! (Login will be faster next time)');

            await cryptoHelper.storeCachedServerKeys(keys);
            updateDebugLog('✅ Server keys cached locally!');

            updateDebugLog('🔄 Step 7: Decrypting RSA private key...');
            try {
                cryptoHelper.privateKey = await cryptoHelper.decryptRSAPrivateKey(keys.encrypted_rsa_private_key, masterKey);
                updateDebugLog('✅ Step 7: RSA private key decrypted! (Double decryption)');
                cryptoHelper.publicKey = await cryptoHelper.importPublicKey(keys.rsa_public_key);
                updateDebugLog('✅ RSA public key loaded!');
            } catch (decryptError) {
                updateDebugLog('❌ Master key mismatch - wrong password or corrupted account');
                throw new Error('Wrong password or corrupted account. Please verify your password or sign up again.');
            }
        } else {
            updateDebugLog('🔄 Step 4: Loading RSA keys...');
            let keys = await cryptoHelper.loadCachedServerKeys();
            if (keys) {
                updateDebugLog('✅ Step 4: Keys loaded from local cache! (No network needed)');
            } else {
                updateDebugLog('🔄 Downloading RSA keys from server...');
                const response = await fetch(`${BACKEND_URL}/api/keys/${data.user.id}`, {
                    headers: { 'Authorization': `Bearer ${data.session.access_token}` },
                });
                if (!response.ok) throw new Error('Failed to fetch encrypted RSA keys from server');
                keys = await response.json();
                updateDebugLog('✅ Step 4: RSA keys downloaded!');
                await cryptoHelper.storeCachedServerKeys(keys);
            }

            updateDebugLog('🔄 Step 5: Decrypting RSA private key with cached master key...');
            try {
                cryptoHelper.privateKey = await cryptoHelper.decryptRSAPrivateKey(keys.encrypted_rsa_private_key, masterKey);
                updateDebugLog('✅ Step 5: RSA private key decrypted!');
                cryptoHelper.publicKey = await cryptoHelper.importPublicKey(keys.rsa_public_key);
                updateDebugLog('✅ RSA public key loaded!');
            } catch (decryptError) {
                updateDebugLog('⚠️ Master key / cached keys mismatch — fetching fresh copies from server...');
                await cryptoHelper.clearMasterKeyFromIndexedDB();
                await cryptoHelper.clearCachedServerKeys();

                updateDebugLog('🔄 Downloading fresh keys from server...');
                const freshResponse = await fetch(`${BACKEND_URL}/api/keys/${data.user.id}`, {
                    headers: { 'Authorization': `Bearer ${data.session.access_token}` },
                });
                if (!freshResponse.ok) throw new Error('Failed to fetch keys from server');
                const freshKeys = await freshResponse.json();

                updateDebugLog('🔄 Decrypting master key with password...');
                masterKey = await cryptoHelper.decryptMasterKeyWithPassword(freshKeys.encrypted_master_key, password);
                updateDebugLog('✅ Master key decrypted!');

                await cryptoHelper.storeMasterKeyInIndexedDB(masterKey);
                await cryptoHelper.storeCachedServerKeys(freshKeys);

                cryptoHelper.privateKey = await cryptoHelper.decryptRSAPrivateKey(freshKeys.encrypted_rsa_private_key, masterKey);
                cryptoHelper.publicKey = await cryptoHelper.importPublicKey(freshKeys.rsa_public_key);
                updateDebugLog('✅ RSA keys recovered and cached!');
            }
        }

        updateDebugLog('🎉 Login complete! All encryption keys ready.');
        showAlert('success', 'Login successful! Loading your chats...');
        await initializeChat();
    } catch (error) {
        console.error('Login error:', error);
        showAlert('error', error.message);
        updateDebugLog(`❌ Error: ${error.message}`);
    }
}

/**
 * Handle logout
 */
async function handleLogout() {
    if (socket) socket.disconnect();

    await supabaseClient.auth.signOut();
    cryptoHelper.clearKeys();
    await cryptoHelper.clearCachedServerKeys();

    currentUser = null;
    socket = null;
    currentChatId = null;
    currentRecipientId = null;
    currentRecipientName = null;
    recentChatsData.clear();
    profileCache.clear();

    chatSection.style.display = 'none';
    authSection.style.display = 'block';

    showAlert('info', 'Logged out successfully');
    updateDebugLog('👋 Logged out');
}

/**
 * Initialize chat interface
 */
async function initializeChat() {
    try {
        const { data: { session } } = await supabaseClient.auth.getSession();
        if (!session) {
            showAlert('error', 'No active session');
            return;
        }

        socket = io(BACKEND_URL, {
            auth: { token: session.access_token },
            timeout: 30000,
            reconnectionAttempts: 5,
            reconnectionDelay: 2000,
            reconnectionDelayMax: 10000,
        });

        socket.on('connect', () => {
            console.log('✅ Connected to Socket.IO server');
            updateChatDebugLog('🟢 Connected to real-time server');
        });

        socket.on('disconnect', () => {
            console.log('❌ Disconnected from Socket.IO server');
            updateChatDebugLog('🔴 Disconnected from server');
        });

        socket.on('reconnecting', (attempt) => {
            updateChatDebugLog(`🔄 Reconnecting to server... (attempt ${attempt})`);
        });

        socket.on('chat:key:received', async (data) => {
            console.log('🔑 Received encrypted chat key:', data);
            try {
                await cryptoHelper.decryptChatKey(data.encrypted_chat_key, data.chatId);
                // Join the socket room so we receive messages for this new chat
                socket.emit('chat:join', { chatId: data.chatId });
                // Add to sidebar if not already present
                if (!recentChatsData.has(data.chatId)) {
                    const profile = data.from ? await getProfile(data.from) : null;
                    const name = getDisplayName(profile, data.from);
                    recentChatsData.set(data.chatId, {
                        name, recipientId: data.from,
                        lastMsg: '', lastTime: new Date().toISOString(), unreadCount: 0,
                    });
                    renderAllChatItems();
                }
            } catch (error) {
                console.error('Failed to decrypt chat key:', error);
            }
        });

        socket.on('message:receive', async (data) => {
            console.log('📨 Message received:', data);
            if (data.sender_id === currentUser.id) return; // skip own echo
            await displayReceivedMessage(data);
        });

        // Show chat UI
        authSection.style.display = 'none';
        chatSection.style.display = 'flex';

        const emailShort = currentUser.email?.split('@')[0] || 'User';
        document.getElementById('currentUser').textContent = currentUser.email;
        const avatarEl = document.getElementById('myAvatar');
        if (avatarEl) avatarEl.textContent = getInitial(emailShort);

        // Load recent chats into sidebar
        await loadRecentChats();

    } catch (error) {
        console.error('Chat init error:', error);
        showAlert('error', 'Failed to initialize chat');
    }
}

/**
 * Open a chat in the main area
 */
async function openChat(chatId, recipientId, name) {
    document.querySelectorAll('.chat-item').forEach(el => el.classList.remove('active'));
    const chatItemEl = document.getElementById(`chat-item-${chatId}`);
    if (chatItemEl) chatItemEl.classList.add('active');

    currentChatId = chatId;
    currentRecipientId = recipientId;
    currentRecipientName = name;

    // Clear unread badge
    const chatData = recentChatsData.get(chatId);
    if (chatData) { chatData.unreadCount = 0; renderAllChatItems(); }

    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('activeChatArea').style.display = 'flex';
    document.getElementById('recipientNameDisplay').textContent = name;
    const topAvatar = document.getElementById('topbarAvatar');
    if (topAvatar) topAvatar.textContent = getInitial(name);

    await ensureChatKey(chatId, recipientId);
    await loadMessageHistory(chatId);
    document.getElementById('messageInput').focus();
}

/**
 * Ensure we have a chat key (local -> server -> generate new)
 */
async function ensureChatKey(chatId, recipientId) {
    const { data: { session } } = await supabaseClient.auth.getSession();

    if (await cryptoHelper.loadChatKey(chatId)) return;

    const keysRes = await fetch(`${BACKEND_URL}/api/chats/${chatId}/keys`, {
        headers: { 'Authorization': `Bearer ${session.access_token}` },
    });
    if (keysRes.ok) {
        const { chat_keys } = await keysRes.json();
        const ourKey = chat_keys.find(k => k.recipient_id === currentUser.id);
        if (ourKey) {
            await cryptoHelper.decryptChatKey(ourKey.encrypted_chat_key, chatId);
            return;
        }
    }

    // Generate new key and share with both parties
    const chatKey = await cryptoHelper.generateChatKey(chatId);
    const myPublicKey = await cryptoHelper.importPublicKey(await cryptoHelper.exportPublicKey());
    const myEncKey = await cryptoHelper.encryptChatKey(chatKey, myPublicKey);
    await fetch(`${BACKEND_URL}/api/chats/${chatId}/share-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${session.access_token}` },
        body: JSON.stringify({ recipient_id: currentUser.id, encrypted_chat_key: myEncKey }),
    });

    const pubRes = await fetch(`${BACKEND_URL}/api/users/${recipientId}/public-key`, {
        headers: { 'Authorization': `Bearer ${session.access_token}` },
    });
    if (!pubRes.ok) throw new Error('Recipient public key not found');
    const { public_key } = await pubRes.json();
    const recipKey = await cryptoHelper.importPublicKey(public_key);
    const recipEncKey = await cryptoHelper.encryptChatKey(chatKey, recipKey);
    await fetch(`${BACKEND_URL}/api/chats/${chatId}/share-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${session.access_token}` },
        body: JSON.stringify({ recipient_id: recipientId, encrypted_chat_key: recipEncKey }),
    });
}

/**
 * Load message history for a chat
 */
async function loadMessageHistory(chatId, retryAttempt = 0) {
    try {
        if (retryAttempt > 1) {
            updateChatDebugLog('⚠️ Already retried once. Old messages encrypted with different key.');
            return;
        }

        updateChatDebugLog(`📜 Loading message history...${retryAttempt > 0 ? ' (retry ' + retryAttempt + ')' : ''}`);

        const messagesDiv = document.getElementById('messages');
        messagesDiv.innerHTML = '';

        const { data: { session } } = await supabaseClient.auth.getSession();

        if (!await cryptoHelper.loadChatKey(chatId)) {
            updateChatDebugLog('🔑 No chat key found locally, fetching from server...');
            const keysResponse = await fetch(`${BACKEND_URL}/api/chats/${chatId}/keys`, {
                headers: { 'Authorization': `Bearer ${session.access_token}` },
            });
            if (keysResponse.ok) {
                const { chat_keys } = await keysResponse.json();
                const ourKey = chat_keys.find(key => key.recipient_id === currentUser.id);
                if (ourKey) {
                    await cryptoHelper.decryptChatKey(ourKey.encrypted_chat_key, chatId);
                    updateChatDebugLog('✅ Chat key downloaded and decrypted');
                }
            }
        }

        const response = await fetch(`${BACKEND_URL}/api/chats/${chatId}/messages?limit=50`, {
            headers: { 'Authorization': `Bearer ${session.access_token}` },
        });
        if (!response.ok) throw new Error('Failed to load message history');

        const { messages } = await response.json();
        updateChatDebugLog(`📜 Loaded ${messages.length} messages`);

        let decryptedCount = 0;
        let failedCount = 0;
        let firstDecryptFailed = false;

        for (const message of messages) {
            try {
                const plaintext = await cryptoHelper.decryptMessage(
                    message.encrypted_content,
                    message.metadata?.iv || '',
                    chatId
                );

                const messageDiv = document.createElement('div');
                const isSent = message.sender_id === currentUser.id;
                messageDiv.className = `msg-group ${isSent ? 'sent' : 'received'}`;
                messageDiv.innerHTML = `
                    <div class="msg-bubble">${escapeHtml(plaintext)}</div>
                    <div class="message-time">${new Date(message.created_at).toLocaleTimeString()}</div>
                `;
                messagesDiv.appendChild(messageDiv);
                decryptedCount++;
            } catch (error) {
                console.error('Failed to decrypt message:', error);
                failedCount++;

                if (!firstDecryptFailed && messages.length > 0) {
                    firstDecryptFailed = true;
                    updateChatDebugLog('⚠️ Decryption failed - wrong cached key, fetching correct one...');
                    localStorage.removeItem(`chatKeys_${chatId}`);

                    try {
                        const keysResponse = await fetch(`${BACKEND_URL}/api/chats/${chatId}/keys`, {
                            headers: { 'Authorization': `Bearer ${session.access_token}` },
                        });
                        if (keysResponse.ok) {
                            const { chat_keys } = await keysResponse.json();
                            const ourKey = chat_keys.find(key => key.recipient_id === currentUser.id);
                            if (ourKey) {
                                const correctKey = await cryptoHelper.decryptChatKey(ourKey.encrypted_chat_key, chatId);
                                if (correctKey) {
                                    updateChatDebugLog('✅ Correct key loaded! Reloading messages...');
                                    return await loadMessageHistory(chatId, retryAttempt + 1);
                                }
                            }
                        }
                    } catch (fetchError) {
                        console.error('Server fetch error:', fetchError);
                    }
                    updateChatDebugLog('❌ Could not fetch correct key from server');
                }

                const messageDiv = document.createElement('div');
                messageDiv.className = 'msg-group received';
                messageDiv.innerHTML = `
                    <div class="msg-bubble" style="color:#888;font-style:italic">🔒 Message encrypted with old keys</div>
                    <div class="message-time">${new Date(message.created_at).toLocaleString()}</div>
                `;
                messagesDiv.appendChild(messageDiv);
            }
        }

        if (failedCount > 0) {
            updateChatDebugLog(`⚠️ ${failedCount} old messages couldn't be decrypted`);
        }
        updateChatDebugLog(`✅ Loaded ${decryptedCount} messages successfully`);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;

    } catch (error) {
        console.error('Failed to load message history:', error);
        updateChatDebugLog(`❌ Error loading history: ${error.message}`);
    }
}

/**
 * Fetch (and cache) a user profile
 */
async function getProfile(userId) {
    if (profileCache.has(userId)) return profileCache.get(userId);
    const { data: { session } } = await supabaseClient.auth.getSession();
    try {
        const r = await fetch(`${BACKEND_URL}/api/users/${userId}`, {
            headers: { 'Authorization': `Bearer ${session.access_token}` },
        });
        if (!r.ok) return null;
        const body = await r.json();
        const profile = body.profile || body;
        profileCache.set(userId, profile);
        return profile;
    } catch { return null; }
}

/**
 * Load recent chats into sidebar
 */
async function loadRecentChats() {
    const { data: { session } } = await supabaseClient.auth.getSession();
    try {
        const r = await fetch(`${BACKEND_URL}/api/chats`, {
            headers: { 'Authorization': `Bearer ${session.access_token}` },
        });
        if (!r.ok) return;
        const { chats } = await r.json();
        for (const chat of (chats || [])) {
            const recipId = chat.participants?.find(p => p !== currentUser.id);
            const profile = recipId ? await getProfile(recipId) : null;
            const name = getDisplayName(profile, recipId);
            // last_message from Supabase join is an array of message objects; we can't show encrypted content
            const lastMsgArr = Array.isArray(chat.last_message) ? chat.last_message : [];
            const lastMsgObj = lastMsgArr.length ? lastMsgArr[lastMsgArr.length - 1] : null;
            const lastMsgTime = lastMsgObj?.created_at || chat.updated_at || chat.created_at;
            recentChatsData.set(chat.id, {
                name,
                recipientId: recipId,
                lastMsg: lastMsgObj ? '🔒 Encrypted message' : '',
                lastTime: lastMsgTime,
                unreadCount: 0,
            });
        }
        renderAllChatItems();
    } catch (e) { console.error('loadRecentChats:', e); }
}

function renderAllChatItems() {
    const list = document.getElementById('recentChats');
    list.innerHTML = '';
    const sorted = [...recentChatsData.entries()]
        .sort((a, b) => new Date(b[1].lastTime) - new Date(a[1].lastTime));
    for (const [chatId, data] of sorted) {
        list.appendChild(renderChatItem(chatId, data));
    }
}

function renderChatItem(chatId, data) {
    const el = document.createElement('div');
    el.className = 'chat-item' + (chatId === currentChatId ? ' active' : '');
    el.id = `chat-item-${chatId}`;
    el.onclick = () => openChat(chatId, data.recipientId, data.name);
    el.innerHTML = `
        <div class="chat-item-avatar">${getInitial(data.name)}</div>
        <div class="chat-item-info">
            <div class="chat-item-name">${escapeHtml(data.name)}</div>
            <div class="chat-item-preview">${escapeHtml(data.lastMsg || 'Tap to open')}</div>
        </div>
        <div class="chat-item-meta">
            <div class="chat-item-time">${formatTime(data.lastTime)}</div>
            ${data.unreadCount ? `<div class="unread-badge">${data.unreadCount}</div>` : ''}
        </div>
    `;
    return el;
}

function updateRecentChat(chatId, msgText, time) {
    const data = recentChatsData.get(chatId);
    if (!data) return;
    data.lastMsg = msgText;
    data.lastTime = time || new Date().toISOString();
    if (chatId !== currentChatId) data.unreadCount = (data.unreadCount || 0) + 1;
    renderAllChatItems();
}

/**
 * Search users by name/email
 */
async function searchUsers(query) {
    const resultsDiv = document.getElementById('searchResults');
    resultsDiv.innerHTML = '<div style="padding:12px;color:#888">Searching\u2026</div>';
    resultsDiv.classList.add('open');
    try {
        const { data: { session } } = await supabaseClient.auth.getSession();
        const r = await fetch(`${BACKEND_URL}/api/users/search/${encodeURIComponent(query)}`, {
            headers: { 'Authorization': `Bearer ${session.access_token}` },
        });
        if (!r.ok) throw new Error('Search failed');
        const { users } = await r.json();
        renderSearchResults(users || []);
    } catch (e) {
        document.getElementById('searchResults').innerHTML = '<div style="padding:12px;color:#f44">Search failed</div>';
    }
}

function renderSearchResults(users) {
    const div = document.getElementById('searchResults');
    if (!users.length) {
        div.innerHTML = '<div style="padding:12px;color:#888">No users found</div>';
        return;
    }
    div.innerHTML = '';
    users.forEach(u => {
        if (u.id === currentUser.id) return;
        const name = getDisplayName(u, u.id);
        const item = document.createElement('div');
        item.className = 'search-result-item';
        item.innerHTML = `
            <div class="search-result-avatar">${getInitial(name)}</div>
            <div>
                <div style="font-weight:600">${escapeHtml(name)}</div>
                <div style="font-size:12px;color:#888">${escapeHtml(u.email || '')}</div>
            </div>
        `;
        item.onclick = () => {
            document.getElementById('searchResults').classList.remove('open');
            document.getElementById('searchInput').value = '';
            startChatWithUser(u.id, name);
        };
        div.appendChild(item);
    });
}

window.startChatWithUser = async function(userId, name) {
    try {
        const { data: { session } } = await supabaseClient.auth.getSession();
        const r = await fetch(`${BACKEND_URL}/api/chats/direct/${userId}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${session.access_token}` },
        });
        if (!r.ok) throw new Error('Failed to create chat');
        const { chat } = await r.json();
        if (!recentChatsData.has(chat.id)) {
            recentChatsData.set(chat.id, {
                name, recipientId: userId,
                lastMsg: '', lastTime: new Date().toISOString(), unreadCount: 0,
            });
            renderAllChatItems();
        }
        // Join socket room for this chat so we receive real-time messages
        if (socket) socket.emit('chat:join', { chatId: chat.id });
        openChat(chat.id, userId, name);
    } catch (e) {
        showAlert('error', e.message);
    }
};

/**
 * Send encrypted message
 */
async function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    if (!message || !currentChatId) return;

    try {
        const { encrypted, iv } = await cryptoHelper.encryptMessage(message, currentChatId);

        displaySentMessage(message);

        socket.emit('message:send', {
            chatId: currentChatId,
            encryptedContent: encrypted,
            iv: iv,
            messageType: 'text',
        });

        input.value = '';
    } catch (error) {
        console.error('Failed to send message:', error);
        showAlert('error', 'Failed to send message');
        updateChatDebugLog(`❌ Error: ${error.message}`);
    }
}

/**
 * Display sent message
 */
function displaySentMessage(plaintext) {
    const messagesDiv = document.getElementById('messages');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'msg-group sent';
    messageDiv.innerHTML = `
        <div class="msg-bubble">${escapeHtml(plaintext)}</div>
        <div class="message-time">${new Date().toLocaleTimeString()}</div>
    `;
    messagesDiv.appendChild(messageDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    updateRecentChat(currentChatId, plaintext, new Date().toISOString());
}

/**
 * Display received message
 */
async function displayReceivedMessage(data) {
    try {
        const chatId = data.chat_id;

        if (!cryptoHelper.chatKeys.has(chatId)) {
            const { data: { session } } = await supabaseClient.auth.getSession();
            if (!session) throw new Error('Not authenticated');
            const response = await fetch(`${BACKEND_URL}/api/chats/${chatId}/my-key`, {
                headers: { 'Authorization': `Bearer ${session.access_token}` },
            });
            if (!response.ok) throw new Error(`Chat key fetch failed: ${response.status}`);
            const { encrypted_chat_key } = await response.json();
            if (!encrypted_chat_key) throw new Error('No chat key returned from server');
            await cryptoHelper.decryptChatKey(encrypted_chat_key, chatId);
        }

        const plaintext = await cryptoHelper.decryptMessage(
            data.encrypted_content, data.iv, chatId
        );

        // If this chat isn't in sidebar yet, add it (new chat started by the other user)
        if (!recentChatsData.has(chatId)) {
            const profile = data.sender_id ? await getProfile(data.sender_id) : null;
            const name = getDisplayName(profile, data.sender_id);
            recentChatsData.set(chatId, {
                name, recipientId: data.sender_id,
                lastMsg: '', lastTime: new Date().toISOString(), unreadCount: 0,
            });
        }
        // Update sidebar preview regardless of active chat
        updateRecentChat(chatId, plaintext, data.created_at || new Date().toISOString());

        // Only display in message area if this is the active chat
        if (chatId !== currentChatId) return;

        const messagesDiv = document.getElementById('messages');
        const messageDiv = document.createElement('div');
        messageDiv.className = 'msg-group received';
        messageDiv.innerHTML = `
            <div class="msg-bubble">${escapeHtml(plaintext)}</div>
            <div class="message-time">${new Date().toLocaleTimeString()}</div>
        `;
        messagesDiv.appendChild(messageDiv);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    } catch (error) {
        console.error('Failed to decrypt message:', error);
        if (data.chat_id === currentChatId) {
            const messagesDiv = document.getElementById('messages');
            const errorDiv = document.createElement('div');
            errorDiv.className = 'msg-group received';
            errorDiv.innerHTML = `<div class="msg-bubble" style="color:#999;font-style:italic">⚠️ Cannot decrypt message</div>`;
            messagesDiv.appendChild(errorDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
    }
}

/**
 * Show recovery key modal
 */
function showRecoveryKey(recoveryKey, email) {
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.85);display:flex;align-items:center;justify-content:center;z-index:10000;';
    modal.innerHTML = `
        <div style="background:#111;color:#fff;padding:36px;border-radius:12px;max-width:540px;width:90%;border:1px solid #333;">
            <h2 style="margin:0 0 16px 0;font-size:20px;">🔑 Account Recovery Key</h2>
            <p style="margin:0 0 16px 0;color:#aaa;font-size:14px;">
                <strong style="color:#fff;">IMPORTANT:</strong> Save this recovery key in a safe place. You need it if you forget your password.
            </p>
            <div style="background:#1a1a1a;padding:16px;border-radius:8px;margin:16px 0;font-family:monospace;font-size:13px;word-break:break-all;border:2px dashed #444;color:#e0e0e0;">
                ${recoveryKey}
            </div>
            <p style="margin:12px 0;color:#777;font-size:13px;">Account: <strong style="color:#ccc;">${email}</strong></p>
            <div style="display:flex;gap:10px;margin-top:16px;">
                <button onclick="copyRecoveryKey('${recoveryKey}')" style="flex:1;padding:12px;background:#fff;color:#111;border:none;border-radius:8px;cursor:pointer;font-weight:700;">
                    📋 Copy
                </button>
                <button onclick="downloadRecoveryKey('${recoveryKey}', '${email}')" style="flex:1;padding:12px;background:#333;color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:700;">
                    💾 Download
                </button>
            </div>
            <button onclick="closeRecoveryModal()" style="width:100%;margin-top:10px;padding:12px;background:#fff;color:#111;border:none;border-radius:8px;cursor:pointer;font-weight:700;">
                ✅ I've Saved My Recovery Key
            </button>
        </div>
    `;
    document.body.appendChild(modal);
    window.recoveryModal = modal;
}

/**
 * Copy recovery key to clipboard
 */
window.copyRecoveryKey = function(key) {
    navigator.clipboard.writeText(key);
    showAlert('success', 'Recovery key copied to clipboard!');
};

/**
 * Download recovery key as file
 */
window.downloadRecoveryKey = function(key, email) {
    const content = [
        'ACCOUNT RECOVERY KEY',
        '====================================',
        `Account: ${email}`,
        `Generated: ${new Date().toLocaleString()}`,
        '',
        'Recovery Key:',
        key,
        '',
        'IMPORTANT: Keep this key safe and secure!',
        '====================================',
    ].join('\n');

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recovery-key-${email}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showAlert('success', 'Recovery key downloaded!');
};

/**
 * Close recovery key modal
 */
window.closeRecoveryModal = function() {
    if (window.recoveryModal) {
        window.recoveryModal.remove();
        window.recoveryModal = null;
    }
};

/**
 * Show alert — uses alertContainer in auth context, toast in chat context
 */
function showAlert(type, message) {
    if (chatSection.style.display === 'flex') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    } else {
        alertContainer.innerHTML = `<div class="alert alert-${type}">${escapeHtml(message)}</div>`;
        setTimeout(() => { alertContainer.innerHTML = ''; }, 5000);
    }
}

/**
 * Update debug log (auth progress panel + console)
 */
function updateDebugLog(message) {
    console.log('[Auth]', message);
    const progress = document.getElementById('authProgress');
    if (progress) {
        progress.classList.add('show');
        const line = document.createElement('div');
        line.textContent = message;
        progress.appendChild(line);
        progress.scrollTop = progress.scrollHeight;
    }
}

/**
 * Update chat debug log (console only)
 */
function updateChatDebugLog(message) {
    console.log('[Chat]', message);
}
