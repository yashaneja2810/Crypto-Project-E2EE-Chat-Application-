import { Router, Response } from 'express';
import { AuthRequest, verifySupabaseToken } from '../middleware/auth';
import { validate } from '../middleware/validation';
import { UserModel } from '../models/user.model';
import { KeysModel } from '../models/keys.model';
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

// Upload/Update public key — legacy endpoint, key upload now uses POST /api/keys
router.post('/public-key', verifySupabaseToken, validate(publicKeySchema), async (_req: AuthRequest, res: Response) => {
  res.status(410).json({ error: 'This endpoint is deprecated. Use POST /api/keys to upload your key bundle.' });
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
