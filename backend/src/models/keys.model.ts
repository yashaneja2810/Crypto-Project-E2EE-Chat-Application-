import { supabaseAdmin } from '../config/supabase';
import { logger } from '../utils/logger';

export interface UserKey {
  user_id: string;
  public_key: string;
  encrypted_master_key: string;
  encrypted_rsa_private_key: string;
  created_at: string;
  updated_at: string;
}

export interface ChatKey {
  id: string;
  chat_id: string;
  sender_id: string;
  recipient_id: string;
  encrypted_chat_key: string;
  created_at: string;
}

export class KeysModel {
  /**
   * Store or update user's public key
   */
  static async upsertPublicKey(userId: string, publicKey: string): Promise<UserKey | null> {
    try {
      const { data, error } = await supabaseAdmin
        .from('user_keys')
        .upsert({
          user_id: userId,
          public_key: publicKey,
          updated_at: new Date().toISOString(),
        })
        .select()
        .single();

      if (error) {
        logger.error('Error upserting public key:', error);
        return null;
      }

      return data;
    } catch (error) {
      logger.error('Error in upsertPublicKey:', error);
      return null;
    }
  }

  /**
   * Get user's public key
   */
  static async getPublicKey(userId: string): Promise<string | null> {
    try {
      const { data, error } = await supabaseAdmin
        .from('user_keys')
        .select('public_key')
        .eq('user_id', userId)
        .single();

      if (error) {
        logger.error('Error fetching public key:', error);
        return null;
      }

      return data?.public_key || null;
    } catch (error) {
      logger.error('Error in getPublicKey:', error);
      return null;
    }
  }

  /**
   * Upload all user keys (master key + ECDH keys)
   */
  static async uploadUserKeys(
    userId: string,
    ecdhPublicKey: string,
    encryptedMasterKey: string,
    encryptedPrivateKey: string
  ): Promise<UserKey | null> {
    try {
      const { data, error } = await supabaseAdmin
        .from('user_keys')
        .upsert({
          user_id: userId,
          public_key: ecdhPublicKey,
          encrypted_master_key: encryptedMasterKey,
          encrypted_rsa_private_key: encryptedPrivateKey,
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

  /**
   * Get all encrypted keys for a user
   */
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

  /**
   * Update encrypted master key (for password change)
   */
  static async updateEncryptedMasterKey(userId: string, encryptedMasterKey: string): Promise<boolean> {
    try {
      const { error } = await supabaseAdmin
        .from('user_keys')
        .update({
          encrypted_master_key: encryptedMasterKey,
          updated_at: new Date().toISOString(),
        })
        .eq('user_id', userId);

      if (error) {
        logger.error('Error updating encrypted master key:', error);
        return false;
      }

      return true;
    } catch (error) {
      logger.error('Error in updateEncryptedMasterKey:', error);
      return false;
    }
  }

  /**
   * Delete all chat keys for a user (when they regenerate keys)
   */
  static async deleteUserChatKeys(userId: string): Promise<boolean> {
    try {
      logger.info(`Deleting all chat keys for user ${userId}...`);
      
      // Delete keys where user is recipient (can't decrypt with new private key)
      const { data: recipientData, error: recipientError } = await supabaseAdmin
        .from('chat_keys')
        .delete()
        .eq('recipient_id', userId)
        .select();

      if (recipientError) {
        logger.error('Error deleting recipient chat keys:', recipientError);
        return false;
      }

      // Delete keys where user is sender (recipient can't use them anymore)
      const { data: senderData, error: senderError } = await supabaseAdmin
        .from('chat_keys')
        .delete()
        .eq('sender_id', userId)
        .select();

      if (senderError) {
        logger.error('Error deleting sender chat keys:', senderError);
        return false;
      }

      const totalDeleted = (recipientData?.length || 0) + (senderData?.length || 0);
      logger.info(`Deleted ${totalDeleted} chat keys for user ${userId} (keys regenerated)`);
      return true;
    } catch (error) {
      logger.error('Error in deleteUserChatKeys:', error);
      return false;
    }
  }

  /**
   * Store encrypted chat key for a recipient
   */
  static async shareChatKey(
    chatId: string,
    senderId: string,
    recipientId: string,
    encryptedChatKey: string
  ): Promise<ChatKey | null> {
    try {
      // Use upsert to handle key rotation scenarios
      const { data, error } = await supabaseAdmin
        .from('chat_keys')
        .upsert({
          chat_id: chatId,
          sender_id: senderId,
          recipient_id: recipientId,
          encrypted_chat_key: encryptedChatKey,
        }, {
          onConflict: 'chat_id,recipient_id'
        })
        .select()
        .single();

      if (error) {
        logger.error('Error sharing chat key:', error);
        return null;
      }

      logger.info(`Chat key shared/updated for chat ${chatId} to recipient ${recipientId}`);
      return data;
    } catch (error) {
      logger.error('Error in shareChatKey:', error);
      return null;
    }
  }

  /**
   * Get encrypted chat key for a specific user in a chat
   */
  static async getChatKey(chatId: string, userId: string): Promise<string | null> {
    try {
      const { data, error } = await supabaseAdmin
        .from('chat_keys')
        .select('encrypted_chat_key')
        .eq('chat_id', chatId)
        .eq('recipient_id', userId)
        .single();

      if (error) {
        logger.error('Error fetching chat key:', error);
        return null;
      }

      return data?.encrypted_chat_key || null;
    } catch (error) {
      logger.error('Error in getChatKey:', error);
      return null;
    }
  }

  /**
   * Get all chat keys for a specific chat (for group key rotation)
   */
  static async getAllChatKeys(chatId: string): Promise<ChatKey[]> {
    try {
      const { data, error } = await supabaseAdmin
        .from('chat_keys')
        .select('*')
        .eq('chat_id', chatId);

      if (error) {
        logger.error('Error fetching all chat keys:', error);
        return [];
      }

      return data || [];
    } catch (error) {
      logger.error('Error in getAllChatKeys:', error);
      return [];
    }
  }

  /**
   * Delete chat keys (useful for group member removal)
   */
  static async deleteChatKey(chatId: string, userId: string): Promise<boolean> {
    try {
      const { error } = await supabaseAdmin
        .from('chat_keys')
        .delete()
        .eq('chat_id', chatId)
        .eq('recipient_id', userId);

      if (error) {
        logger.error('Error deleting chat key:', error);
        return false;
      }

      return true;
    } catch (error) {
      logger.error('Error in deleteChatKey:', error);
      return false;
    }
  }

  /**
   * Get all chats where user has keys (user's active chats)
   */
  static async getUserChats(userId: string): Promise<string[]> {
    try {
      const { data, error } = await supabaseAdmin
        .from('chat_keys')
        .select('chat_id')
        .eq('recipient_id', userId);

      if (error) {
        logger.error('Error fetching user chats:', error);
        return [];
      }

      return data?.map((row) => row.chat_id) || [];
    } catch (error) {
      logger.error('Error in getUserChats:', error);
      return [];
    }
  }
}
