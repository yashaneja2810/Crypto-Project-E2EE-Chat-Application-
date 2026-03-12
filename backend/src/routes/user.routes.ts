import { Router, Response } from 'express';
import { AuthRequest, verifySupabaseToken } from '../middleware/auth';
import { validate } from '../middleware/validation';
import { UserModel } from '../models/user.model';
import { KeysModel } from '../models/keys.model';
import { logger } from '../utils/logger';
import Joi from 'joi';

const router = Router();

// Validation schemas
const updateProfileSchema = Joi.object({
  username: Joi.string().min(3).max(30).optional(),
  display_name: Joi.string().min(1).max(50).optional(),
  avatar_url: Joi.string().uri().optional(),
});

const updatePrivacySchema = Joi.object({
  who_can_add_friend: Joi.string().valid('everyone', 'friends_of_friends', 'nobody').optional(),
  who_can_message: Joi.string().valid('everyone', 'friends', 'nobody').optional(),
  read_receipts: Joi.boolean().optional(),
  typing_indicators: Joi.boolean().optional(),
  online_status: Joi.boolean().optional(),
});

const publicKeySchema = Joi.object({
  public_key: Joi.string().required(),
});

// Get user profile by ID
router.get('/:userId', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const profile = await UserModel.getProfile(req.params.userId);
    
    if (!profile) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    res.json({ profile });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

// Update current user profile
router.patch('/me', verifySupabaseToken, validate(updateProfileSchema), async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const profile = await UserModel.upsertProfile(userId, req.user!.email, req.body);

    res.json({ profile });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Update privacy settings
router.patch('/me/privacy', verifySupabaseToken, validate(updatePrivacySchema), async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const success = await UserModel.updatePrivacySettings(userId, req.body);

    if (!success) {
      res.status(500).json({ error: 'Failed to update privacy settings' });
      return;
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update privacy settings' });
  }
});

// Search users
router.get('/search/:query', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const users = await UserModel.searchUsers(req.params.query);
    res.json({ users });
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// Upload/Update public key (RSA)
router.post('/public-key', verifySupabaseToken, validate(publicKeySchema), async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const { public_key } = req.body;

    logger.info(`Public key upload request from user ${userId}`);

    // Check if user already has a public key (key rotation scenario)
    const existingKey = await KeysModel.getPublicKey(userId);
    const isKeyRotation = !!existingKey;

    if (isKeyRotation) {
      logger.info(`Key rotation detected for user ${userId} (existing key found)`);
    } else {
      logger.info(`First time key upload for user ${userId}`);
    }

    const result = await KeysModel.upsertPublicKey(userId, public_key);

    if (!result) {
      res.status(500).json({ error: 'Failed to store public key' });
      return;
    }

    logger.info(`Public key upserted successfully for user ${userId}`);

    // If this is a key rotation (user regenerated keys), delete old chat keys
    // They can't be decrypted with the new private key anyway
    if (isKeyRotation) {
      const deleteSuccess = await KeysModel.deleteUserChatKeys(userId);
      logger.info(`Chat keys deletion ${deleteSuccess ? 'succeeded' : 'failed'} for user ${userId}`);
    }

    res.json({ 
      success: true, 
      message: 'Public key stored successfully',
      key_rotation: isKeyRotation 
    });
  } catch (error) {
    logger.error('Error in public-key endpoint:', error);
    res.status(500).json({ error: 'Failed to store public key' });
  }
});

// Get user's public key bundle (anyone can access - public keys are meant to be shared!)
router.get('/:userId/public-key', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const { userId } = req.params;

    const bundle = await KeysModel.getPublicKeyBundle(userId);

    if (!bundle) {
      res.status(404).json({ error: 'Public key not found' });
      return;
    }

    res.json(bundle);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch public key' });
  }
});

export default router;
