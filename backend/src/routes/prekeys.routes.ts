import { Router, Response } from 'express';
import { AuthRequest, verifySupabaseToken } from '../middleware/auth';
import { PrekeysModel } from '../models/prekeys.model';
import { logger } from '../utils/logger';
import Joi from 'joi';

const router = Router();

const uploadPrekeysSchema = Joi.object({
  prekeys: Joi.array()
    .items(
      Joi.object({
        public_key: Joi.string().required(),
        signature: Joi.string().required(),
      })
    )
    .min(1)
    .required(),
});

/**
 * POST /api/prekeys
 * Upload a batch of signed X25519 prekeys for the authenticated user.
 */
router.post('/', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const { error } = uploadPrekeysSchema.validate(req.body);
    if (error) {
      res.status(400).json({ error: error.details[0].message });
      return;
    }

    const userId = req.user!.id;
    const { prekeys } = req.body as { prekeys: Array<{ public_key: string; signature: string }> };

    const ok = await PrekeysModel.uploadPrekeys(userId, prekeys);
    if (!ok) {
      res.status(500).json({ error: 'Failed to upload prekeys' });
      return;
    }

    logger.info(`Uploaded ${prekeys.length} prekeys for user ${userId}`);
    res.json({ message: 'Prekeys uploaded successfully', count: prekeys.length });
  } catch (err) {
    logger.error('Error uploading prekeys:', err);
    res.status(500).json({ error: 'Failed to upload prekeys' });
  }
});

/**
 * GET /api/prekeys/:userId
 * Fetch and consume one prekey for the target user.
 * Used by the initiating party to set up a forward-secret session.
 * Requires authentication (must be logged in) but any user can fetch another's prekey.
 */
/**
 * GET /api/prekeys/count/me
 * Returns the authenticated user's remaining prekey count.
 * Used by the client to decide whether to replenish.
 */
router.get('/count/me', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const remaining = await PrekeysModel.getPrekeyCount(userId);
    res.json({ remaining });
  } catch (err) {
    logger.error('Error getting prekey count:', err);
    res.status(500).json({ error: 'Failed to get prekey count' });
  }
});

router.get('/:userId', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const { userId } = req.params;

    const prekey = await PrekeysModel.consumePrekey(userId);
    if (!prekey) {
      res.status(404).json({ error: 'No prekeys available for this user' });
      return;
    }

    res.json({
      prekey_id: prekey.id,
      public_key: prekey.public_key,
      signature: prekey.signature,
    });
  } catch (err) {
    logger.error('Error fetching prekey:', err);
    res.status(500).json({ error: 'Failed to fetch prekey' });
  }
});

export { router as prekeysRouter };
