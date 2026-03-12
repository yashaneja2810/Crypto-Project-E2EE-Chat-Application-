import { Router, Response } from 'express';
import { AuthRequest, verifySupabaseToken } from '../middleware/auth';
import { validate } from '../middleware/validation';
import { ChatModel } from '../models/chat.model';
import { UserModel } from '../models/user.model';
import { MessageModel } from '../models/message.model';
import Joi from 'joi';

const router = Router();

// Validation schemas
const createChatSchema = Joi.object({
  type: Joi.string().valid('direct', 'group').required(),
  participant_ids: Joi.array().items(Joi.string().uuid()).min(1).required(),
});

// Get all user chats
router.get('/', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const chats = await ChatModel.getUserChats(userId);
    res.json({ chats });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get chats' });
  }
});

// Get specific chat
router.get('/:chatId', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const chatId = req.params.chatId;

    const chat = await ChatModel.getChatById(chatId);

    if (!chat) {
      res.status(404).json({ error: 'Chat not found' });
      return;
    }

    // Verify user is in chat
    if (!chat.participants.includes(userId)) {
      res.status(403).json({ error: 'Not authorized' });
      return;
    }

    res.json({ chat });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get chat' });
  }
});

// Create new chat
router.post('/', verifySupabaseToken, validate(createChatSchema), async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const { type, participant_ids } = req.body;

    // Add creator to participants if not already included
    const participants = [...new Set([userId, ...participant_ids])];

    const chat = await ChatModel.createChat(type, userId, participants);

    if (!chat) {
      res.status(400).json({ error: 'Failed to create chat' });
      return;
    }

    res.json({ chat });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create chat' });
  }
});

// Get or create direct chat with a user
router.post('/direct/:userId', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const currentUserId = req.user!.id;
    const otherUserId = req.params.userId;

    if (currentUserId === otherUserId) {
      res.status(400).json({ error: 'Cannot create chat with yourself' });
      return;
    }

    // Ensure both users have profiles
    let currentUserProfile = await UserModel.getProfile(currentUserId);
    if (!currentUserProfile) {
      // Create profile if it doesn't exist
      currentUserProfile = await UserModel.upsertProfile(currentUserId, req.user!.email);
      if (!currentUserProfile) {
        res.status(500).json({ error: 'Failed to create your user profile' });
        return;
      }
    }

    const otherUserProfile = await UserModel.getProfile(otherUserId);
    if (!otherUserProfile) {
      res.status(404).json({ error: 'Recipient user not found' });
      return;
    }

    // Try to get existing direct chat
    let chat = await ChatModel.getDirectChat(currentUserId, otherUserId);

    // Create if doesn't exist
    if (!chat) {
      chat = await ChatModel.createChat('direct', currentUserId, [currentUserId, otherUserId]);
    }

    if (!chat) {
      res.status(400).json({ error: 'Failed to create chat' });
      return;
    }

    res.json({ chat });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get or create chat' });
  }
});

// Share-key / my-key / keys endpoints removed: in the new X25519 design,
// chat keys are derived locally via ECDH and never stored on the server.

// Get chat messages (history)
router.get('/:chatId/messages', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const { chatId } = req.params;
    const limit = parseInt(req.query.limit as string) || 50;
    const before = req.query.before as string;

    // Verify user is in chat
    const chat = await ChatModel.getChatById(chatId);
    if (!chat) {
      res.status(404).json({ error: 'Chat not found' });
      return;
    }

    if (!chat.participants.includes(userId)) {
      res.status(403).json({ error: 'Not authorized' });
      return;
    }

    // Get messages (pass userId so deleted_for filtering works)
    const messages = await MessageModel.getMessages(chatId, limit, before, userId);

    res.json({ messages });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

export default router;
