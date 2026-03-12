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

export class KeysModel {
  static async uploadUserKeys(
    userId: string,
    ecdhPublicKey: string,
    signingPublicKey: string | null,
    devicePublicKey: string | null,
    deviceKeySignature: string | null,
    encryptedMasterKey: string,
    encryptedPrivateKey: string,
    encryptedSigningKey: string | null
  ): Promise<UserKey | null> {
    try {
      const { data, error } = await supabaseAdmin
        .from('user_keys')
        .upsert({
          user_id: userId,
          public_key: ecdhPublicKey,
          signing_public_key: signingPublicKey,
          device_public_key: devicePublicKey,
          device_key_signature: deviceKeySignature,
          encrypted_master_key: encryptedMasterKey,
          encrypted_rsa_private_key: encryptedPrivateKey,
          encrypted_signing_key: encryptedSigningKey,
          updated_at: new Date().toISOString(),
        })
        .select()
        .single();

      if (error) {
        logger.error('Error uploading user keys:', error);
        return null;
      }
      return data;
    } catch (error) {
      logger.error('Error in uploadUserKeys:', error);
      return null;
    }
  }

  static async getUserKeys(userId: string): Promise<UserKey | null> {
    try {
      const { data, error } = await supabaseAdmin
        .from('user_keys')
        .select('*')
        .eq('user_id', userId)
        .single();

      if (error) {
        logger.error('Error fetching user keys:', error);
        return null;
      }
      return data;
    } catch (error) {
      logger.error('Error in getUserKeys:', error);
      return null;
    }
  }

  static async getPublicKey(userId: string): Promise<string | null> {
    try {
      const { data, error } = await supabaseAdmin
        .from('user_keys')
        .select('public_key')
        .eq('user_id', userId)
        .single();

      if (error) return null;
      return data?.public_key || null;
    } catch {
      return null;
    }
  }

  // Returns the full public key bundle (X25519 + Ed25519 signing + device key) for a user
  static async getPublicKeyBundle(userId: string): Promise<{
    public_key: string;
    signing_public_key: string | null;
    device_public_key: string | null;
    device_key_signature: string | null;
  } | null> {
    try {
      const { data, error } = await supabaseAdmin
        .from('user_keys')
        .select('public_key, signing_public_key, device_public_key, device_key_signature')
        .eq('user_id', userId)
        .single();

      if (error) return null;
      return data;
    } catch {
      return null;
    }
  }

  static async updateEncryptedMasterKey(userId: string, encryptedMasterKey: string): Promise<boolean> {
    try {
      const { error } = await supabaseAdmin
        .from('user_keys')
        .update({ encrypted_master_key: encryptedMasterKey, updated_at: new Date().toISOString() })
        .eq('user_id', userId);
      return !error;
    } catch {
      return false;
    }
  }
}