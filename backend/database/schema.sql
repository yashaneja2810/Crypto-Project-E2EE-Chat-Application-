-- Privacy-First Chat Application Database Schema
-- This schema is designed for Supabase PostgreSQL

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- User Profiles Table
CREATE TABLE user_profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE,
    username TEXT UNIQUE,
    display_name TEXT,
    avatar_url TEXT,
    status TEXT CHECK (status IN ('online', 'offline', 'away')) DEFAULT 'offline',
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    privacy_settings JSONB DEFAULT '{
        "who_can_add_friend": "everyone",
        "who_can_message": "friends",
        "read_receipts": true,
        "typing_indicators": true,
        "online_status": true
    }'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User Keys Table (master key + asymmetric keys)
CREATE TABLE user_keys (
    user_id UUID PRIMARY KEY REFERENCES user_profiles(id) ON DELETE CASCADE,
    encrypted_master_key TEXT,          -- Master key encrypted with Argon2id-derived key
    encrypted_rsa_private_key TEXT,     -- X25519 private key encrypted with master key (column name kept for DB compat)
    public_key TEXT NOT NULL,           -- X25519 public key (base64 raw 32 bytes)
    signing_public_key TEXT,            -- Ed25519 identity signing public key (base64 raw)
    device_public_key TEXT,             -- Ed25519 device identity public key (base64 raw)
    device_key_signature TEXT,          -- Signature of x25519 public_key by device_public_key
    encrypted_signing_key TEXT,         -- Ed25519 signing private key encrypted with master key
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON COLUMN user_keys.encrypted_master_key IS 'Master encryption key encrypted with Argon2id-derived key. Server cannot decrypt this.';
COMMENT ON COLUMN user_keys.encrypted_rsa_private_key IS 'X25519 private key encrypted with master key (column name kept for backward compat).';
COMMENT ON COLUMN user_keys.public_key IS 'X25519 static public key used for key agreement (base64-encoded raw 32 bytes).';
COMMENT ON COLUMN user_keys.signing_public_key IS 'Ed25519 public key used to verify message signatures.';
COMMENT ON COLUMN user_keys.device_public_key IS 'Ed25519 device identity key — proves which device uploaded these keys.';
COMMENT ON COLUMN user_keys.device_key_signature IS 'Signature of public_key by device_public_key — binds device identity to user key.';
COMMENT ON COLUMN user_keys.encrypted_signing_key IS 'Ed25519 signing private key encrypted with master key.';;

-- Friends/Relationships Table
CREATE TABLE friends (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    friend_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    status TEXT CHECK (status IN ('pending', 'accepted', 'blocked')) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, friend_id)
);

-- Chats Table
CREATE TABLE chats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type TEXT CHECK (type IN ('direct', 'group')) NOT NULL,
    participants UUID[] NOT NULL,
    created_by UUID NOT NULL REFERENCES user_profiles(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Chat Keys Table (stores encrypted symmetric keys for each participant)
CREATE TABLE chat_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    sender_id UUID NOT NULL REFERENCES user_profiles(id),
    recipient_id UUID NOT NULL REFERENCES user_profiles(id),
    encrypted_chat_key TEXT NOT NULL, -- Chat key encrypted with recipient's public key
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(chat_id, recipient_id)
);

-- Messages Table (stores encrypted content only)
CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    sender_id UUID NOT NULL REFERENCES user_profiles(id),
    encrypted_content TEXT NOT NULL, -- Base64 encoded encrypted blob
    message_type TEXT CHECK (message_type IN ('text', 'image', 'file', 'voice')) DEFAULT 'text',
    metadata JSONB, -- For file info, etc. (not sensitive)
    status TEXT CHECK (status IN ('sent', 'delivered', 'read')) DEFAULT 'sent',
    encryption_key_id TEXT NOT NULL DEFAULT 'default', -- Reference to which key was used
    reply_to UUID REFERENCES messages(id),
    expires_at TIMESTAMP WITH TIME ZONE, -- For self-destructing messages
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Groups Table
CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    avatar_url TEXT,
    admin_ids UUID[] NOT NULL,
    member_ids UUID[] NOT NULL,
    created_by UUID NOT NULL REFERENCES user_profiles(id),
    settings JSONB DEFAULT '{
        "only_admins_can_message": false,
        "only_admins_can_add_members": false,
        "invite_link_enabled": false,
        "invite_link": null
    }'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Backups Table
CREATE TABLE backups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    google_email TEXT NOT NULL,
    drive_file_id TEXT,
    backup_size BIGINT NOT NULL,
    encrypted_hash TEXT NOT NULL, -- Hash for integrity verification
    status TEXT CHECK (status IN ('pending', 'completed', 'failed')) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Device Verification Table (for multi-device support)
CREATE TABLE device_verifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    verification_code TEXT NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() + INTERVAL '10 minutes',
    UNIQUE(user_id, device_id)
);

-- Anonymous/Temporary Chats Table (Advanced Feature)
CREATE TABLE anonymous_chats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Prekeys Table (X3DH-style ephemeral prekeys for forward secrecy)
-- Public halves of one-time X25519 prekeys, each signed with the user's Ed25519 signing key.
-- Consumed (deleted) upon first use so each prekey is used at most once.
CREATE TABLE prekeys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES user_profiles(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,   -- X25519 prekey public key (base64 raw 32 bytes)
    signature TEXT NOT NULL,    -- Ed25519 signature of public_key by user's signing_public_key
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_user_keys_user_id ON user_keys(user_id);
CREATE INDEX idx_prekeys_user_id ON prekeys(user_id);
CREATE INDEX idx_chat_keys_chat_id ON chat_keys(chat_id);
CREATE INDEX idx_chat_keys_recipient_id ON chat_keys(recipient_id);

CREATE INDEX idx_friends_user_id ON friends(user_id);
CREATE INDEX idx_friends_friend_id ON friends(friend_id);
CREATE INDEX idx_friends_status ON friends(status);

CREATE INDEX idx_messages_chat_id ON messages(chat_id);
CREATE INDEX idx_messages_sender_id ON messages(sender_id);
CREATE INDEX idx_messages_created_at ON messages(created_at DESC);
CREATE INDEX idx_messages_expires_at ON messages(expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX idx_chats_participants ON chats USING GIN(participants);

CREATE INDEX idx_groups_member_ids ON groups USING GIN(member_ids);
CREATE INDEX idx_groups_admin_ids ON groups USING GIN(admin_ids);

CREATE INDEX idx_backups_user_id ON backups(user_id);

-- Row Level Security (RLS) Policies

-- Enable RLS
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE friends ENABLE ROW LEVEL SECURITY;
ALTER TABLE chats ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE backups ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE anonymous_chats ENABLE ROW LEVEL SECURITY;
ALTER TABLE prekeys ENABLE ROW LEVEL SECURITY;

-- User Profiles Policies
CREATE POLICY "Users can view all profiles" ON user_profiles
    FOR SELECT USING (true);

CREATE POLICY "Users can update own profile" ON user_profiles
    FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Users can insert own profile" ON user_profiles
    FOR INSERT WITH CHECK (auth.uid() = id);

-- User Keys Policies (Public keys are safe to share)
CREATE POLICY "Anyone can view public keys" ON user_keys
    FOR SELECT USING (true);

CREATE POLICY "Users can insert own public key" ON user_keys
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own public key" ON user_keys
    FOR UPDATE USING (auth.uid() = user_id);

-- Prekeys Policies
-- Anyone authenticated can read a prekey (needed to initiate forward-secret sessions)
CREATE POLICY "Anyone can select one prekey" ON prekeys
    FOR SELECT USING (true);

-- Only the owner can upload their prekeys
CREATE POLICY "Users can insert own prekeys" ON prekeys
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Only the owner (or the server via service role) can delete consumed prekeys
CREATE POLICY "Users can delete own prekeys" ON prekeys
    FOR DELETE USING (auth.uid() = user_id);

-- Friends Policies
CREATE POLICY "Users can view own friends" ON friends
    FOR SELECT USING (auth.uid() = user_id OR auth.uid() = friend_id);

CREATE POLICY "Users can manage own friends" ON friends
    FOR ALL USING (auth.uid() = user_id);

-- Chats Policies
CREATE POLICY "Users can view chats they're in" ON chats
    FOR SELECT USING (auth.uid() = ANY(participants));

CREATE POLICY "Users can create chats" ON chats
    FOR INSERT WITH CHECK (auth.uid() = created_by);

-- Chat Keys Policies (Users can only see keys meant for them)
CREATE POLICY "Users can view their encrypted chat keys" ON chat_keys
    FOR SELECT USING (auth.uid() = recipient_id);

CREATE POLICY "Users can insert chat keys for others" ON chat_keys
    FOR INSERT WITH CHECK (auth.uid() = sender_id);

-- Messages Policies
CREATE POLICY "Users can view messages in their chats" ON messages
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM chats
            WHERE chats.id = messages.chat_id
            AND auth.uid() = ANY(chats.participants)
        )
    );

CREATE POLICY "Users can send messages to their chats" ON messages
    FOR INSERT WITH CHECK (
        auth.uid() = sender_id AND
        EXISTS (
            SELECT 1 FROM chats
            WHERE chats.id = chat_id
            AND auth.uid() = ANY(chats.participants)
        )
    );

CREATE POLICY "Users can update own messages" ON messages
    FOR UPDATE USING (auth.uid() = sender_id);

-- Groups Policies
CREATE POLICY "Users can view groups they're in" ON groups
    FOR SELECT USING (auth.uid() = ANY(member_ids));

CREATE POLICY "Users can create groups" ON groups
    FOR INSERT WITH CHECK (auth.uid() = created_by);

CREATE POLICY "Admins can update groups" ON groups
    FOR UPDATE USING (auth.uid() = ANY(admin_ids));

-- Backups Policies
CREATE POLICY "Users can manage own backups" ON backups
    FOR ALL USING (auth.uid() = user_id);

-- Device Verifications Policies
CREATE POLICY "Users can manage own devices" ON device_verifications
    FOR ALL USING (auth.uid() = user_id);

-- Functions and Triggers

-- Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER update_user_profiles_updated_at BEFORE UPDATE ON user_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_friends_updated_at BEFORE UPDATE ON friends
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_chats_updated_at BEFORE UPDATE ON chats
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_groups_updated_at BEFORE UPDATE ON groups
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to clean up expired messages
CREATE OR REPLACE FUNCTION cleanup_expired_messages()
RETURNS void AS $$
BEGIN
    DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Function to clean up expired device verifications
CREATE OR REPLACE FUNCTION cleanup_expired_verifications()
RETURNS void AS $$
BEGIN
    DELETE FROM device_verifications WHERE expires_at < NOW() AND NOT verified;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up expired anonymous chats
CREATE OR REPLACE FUNCTION cleanup_expired_anonymous_chats()
RETURNS void AS $$
BEGIN
    DELETE FROM chats WHERE id IN (
        SELECT chat_id FROM anonymous_chats WHERE expires_at < NOW()
    );
    DELETE FROM anonymous_chats WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;
