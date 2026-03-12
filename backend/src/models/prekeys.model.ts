import { supabaseAdmin } from '../config/supabase';
import { logger } from '../utils/logger';

export interface Prekey {
  id: string;
  user_id: string;
  public_key: string;   // X25519 prekey public key (base64 raw)
  signature: string;    // Ed25519 signature of public_key by user's signing key
  created_at: string;
}

export class PrekeysModel {
  /**
   * Upload a batch of prekeys for a user.
   * Each prekey must have { public_key, signature }.
   */
  static async uploadPrekeys(
    userId: string,
    prekeys: Array<{ public_key: string; signature: string }>
  ): Promise<boolean> {
    try {
      const rows = prekeys.map((pk) => ({
        user_id: userId,
        public_key: pk.public_key,
        signature: pk.signature,
      }));

      const { error } = await supabaseAdmin.from('prekeys').insert(rows);

      if (error) {
        logger.error('Error uploading prekeys:', error);
        return false;
      }
      return true;
    } catch (error) {
      logger.error('Error in uploadPrekeys:', error);
      return false;
    }
  }

  /**
   * Fetch and consume one prekey for a user (oldest first).
   * Returns the prekey then deletes it so it cannot be reused.
   */
  static async consumePrekey(userId: string): Promise<Prekey | null> {
    try {
      // Fetch the oldest unused prekey
      const { data, error } = await supabaseAdmin
        .from('prekeys')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: true })
        .limit(1)
        .single();

      if (error || !data) {
        if (error?.code !== 'PGRST116') {
          logger.error('Error fetching prekey:', error);
        }
        return null;
      }

      // Delete the consumed prekey
      const { error: deleteError } = await supabaseAdmin
        .from('prekeys')
        .delete()
        .eq('id', data.id);

      if (deleteError) {
        logger.error('Error deleting consumed prekey:', deleteError);
        // Still return the key — the caller got their prekey
      }

      return data as Prekey;
    } catch (error) {
      logger.error('Error in consumePrekey:', error);
      return null;
    }
  }

  /**
   * Return the number of remaining prekeys for a user.
   */
  static async getPrekeyCount(userId: string): Promise<number> {
    try {
      const { count, error } = await supabaseAdmin
        .from('prekeys')
        .select('id', { count: 'exact', head: true })
        .eq('user_id', userId);

      if (error) return 0;
      return count ?? 0;
    } catch {
      return 0;
    }
  }
}
