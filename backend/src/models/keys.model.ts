import { supabaseAdmin } from '../config/supabase';
import { logger } from '../utils/logger';

export interface UserKey {
  user_id: string;
  public_key: string;                    // X25519 public key (base64 raw)
  signing_public_key: string | null;     // Ed25519 verify key (base64 raw)
  device_public_key: string | null;      // Ed25519 device identity verify key
  device_key_signature: string | null;   // Signature of x25519_pub by device_signing_key
  encrypted_master_key: string;          // Argon2id-wrapped master key
  encrypted_rsa_private_key: string;     // X25519 private key encrypted with master key (field name kept for DB compat)
  encrypted_signing_key: string | null;  // Ed25519 signing private key encrypted with master key
  created_at: string;
  updated_at: string;
}