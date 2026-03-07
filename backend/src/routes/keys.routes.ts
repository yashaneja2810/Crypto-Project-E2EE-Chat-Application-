import { Router, Response } from 'express';
import { AuthRequest, verifySupabaseToken } from '../middleware/auth';
import { KeysModel } from '../models/keys.model';
import { logger } from '../utils/logger';
import Joi from 'joi';

const router = Router();

// Validation schemas
const uploadKeysSchema = Joi.object({
    ecdh_public_key: Joi.string().required(),
    encrypted_master_key: Joi.object({
        wrapped: Joi.string().required(),
        iv: Joi.string().required(),
        salt: Joi.string().required()
    }).required(),
    encrypted_private_key: Joi.object({
        encrypted: Joi.string().required(),
        iv: Joi.string().required()
    }).required()
});

const updateMasterKeySchema = Joi.object({
    encrypted_master_key: Joi.object({
        wrapped: Joi.string().required(),
        iv: Joi.string().required(),
        salt: Joi.string().required()
    }).required()
});

/**
 * Upload user keys (master key + RSA keys)
 */
router.post('/', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
    try {
        const { error } = uploadKeysSchema.validate(req.body);
        if (error) {
            res.status(400).json({ error: error.details[0].message });
            return;
        }

        const { ecdh_public_key, encrypted_master_key, encrypted_private_key } = req.body;
        const userId = req.user!.id;

        await KeysModel.uploadUserKeys(
            userId,
            ecdh_public_key,
            JSON.stringify(encrypted_master_key),
            JSON.stringify(encrypted_private_key)
        );

        logger.info('✅ User keys uploaded:', userId);
        res.json({ message: 'Keys uploaded successfully' });
    } catch (error) {
        logger.error('Error uploading keys:', error);
        res.status(500).json({ error: 'Failed to upload keys' });
    }
});

/**
 * Get user encrypted keys (for device sync)
 */
router.get('/:userId', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
    try {
        const { userId } = req.params;

        // User can only fetch their own keys
        if (userId !== req.user!.id) {
            res.status(403).json({ error: 'Forbidden' });
            return;
        }

        const keys = await KeysModel.getUserKeys(userId);
        if (!keys) {
            res.status(404).json({ error: 'Keys not found' });
            return;
        }

        res.json({
            encrypted_master_key: JSON.parse(keys.encrypted_master_key),
            encrypted_private_key: JSON.parse(keys.encrypted_rsa_private_key),
            ecdh_public_key: keys.public_key
        });
    } catch (error) {
        logger.error('Error getting keys:', error);
        res.status(500).json({ error: 'Failed to get keys' });
    }
});

/**
 * Update encrypted master key (for password change)
 */
router.patch('/', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
    try {
        const { error } = updateMasterKeySchema.validate(req.body);
        if (error) {
            res.status(400).json({ error: error.details[0].message });
            return;
        }

        const { encrypted_master_key } = req.body;
        const userId = req.user!.id;

        await KeysModel.updateEncryptedMasterKey(
            userId,
            JSON.stringify(encrypted_master_key)
        );

        logger.info('✅ Master key updated for user:', userId);
        res.json({ message: 'Master key updated successfully' });
    } catch (error) {
        logger.error('Error updating master key:', error);
        res.status(500).json({ error: 'Failed to update master key' });
    }
});

export { router as keysRouter };