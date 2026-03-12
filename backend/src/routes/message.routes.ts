import { Router, Response } from 'express';
import { AuthRequest, verifySupabaseToken } from '../middleware/auth';
import { validate } from '../middleware/validation';
import { MessageModel } from '../models/message.model';
import { ChatModel } from '../models/chat.model';
import Joi from 'joi';

const router = Router();

// Validation schemas
const sendMessageSchema = Joi.object({
  chat_id: Joi.string().uuid().required(),
  encrypted_content: Joi.string().required(),
  message_type: Joi.string().valid('text', 'image', 'file', 'voice').required(),
  metadata: Joi.object().optional(),
  encryption_key_id: Joi.string().optional(),
  expires_at: Joi.date().iso().optional(),
  reply_to: Joi.string().uuid().optional(),
});

// Get messages for a chat
router.get('/:chatId', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const chatId = req.params.chatId;
    const limit = parseInt(req.query.limit as string) || 50;
    const before = req.query.before as string;

    // Verify user is in chat
    const isInChat = await ChatModel.isUserInChat(chatId, userId);
    if (!isInChat) {
      res.status(403).json({ error: 'Not authorized' });
      return;
    }

    const messages = await MessageModel.getMessages(chatId, limit, before, userId);
    res.json({ messages });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get messages' });
  }
});

// Send message (also available via WebSocket)
router.post('/', verifySupabaseToken, validate(sendMessageSchema), async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const {
      chat_id,
      encrypted_content,
      message_type,
      metadata,
      encryption_key_id,
      expires_at,
      reply_to,
    } = req.body;

    // Verify user is in chat
    const isInChat = await ChatModel.isUserInChat(chat_id, userId);
    if (!isInChat) {
      res.status(403).json({ error: 'Not authorized' });
      return;
    }

    const message = await MessageModel.createMessage(
      chat_id,
      userId,
      encrypted_content,
      message_type,
      metadata,
      encryption_key_id,
      expires_at ? new Date(expires_at) : undefined,
      reply_to
    );

    if (!message) {
      res.status(400).json({ error: 'Failed to send message' });
      return;
    }

    res.json({ message });
  } catch (error) {
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Clear all messages in a chat
router.delete('/chat/:chatId/clear', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const chatId = req.params.chatId;

    const { ChatModel } = await import('../models/chat.model');
    const isInChat = await ChatModel.isUserInChat(chatId, userId);
    if (!isInChat) {
      res.status(403).json({ error: 'Not authorized for this chat' });
      return;
    }

    const success = await MessageModel.clearChat(chatId);
    if (!success) {
      res.status(500).json({ error: 'Failed to clear chat' });
      return;
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to clear chat' });
  }
});

// Unsend message (removes for everyone, sender only)
router.delete('/:messageId/unsend', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const messageId = req.params.messageId;

    const result = await MessageModel.unsendMessage(messageId, userId);
    if (!result) {
      res.status(400).json({ error: 'Failed to unsend message (only sender can unsend)' });
      return;
    }

    // Broadcast to chat room so other user sees the unsend in real-time
    const io = req.app.get('io');
    if (io) {
      io.to(`chat:${result.chatId}`).emit('message:unsend', { messageId, chatId: result.chatId });
    }

    res.json({ success: true, chatId: result.chatId });
  } catch (error) {
    res.status(500).json({ error: 'Failed to unsend message' });
  }
});

// Delete message for me only (hides from my view)
router.delete('/:messageId/delete-for-me', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const messageId = req.params.messageId;

    const success = await MessageModel.deleteForMe(messageId, userId);
    if (!success) {
      res.status(400).json({ error: 'Failed to delete message' });
      return;
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// Get unread count for a chat
router.get('/:chatId/unread', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const chatId = req.params.chatId;

    const count = await MessageModel.getUnreadCount(chatId, userId);
    res.json({ count });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get unread count' });
  }
});

// Mark messages as read
router.post('/:chatId/read', verifySupabaseToken, async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user!.id;
    const chatId = req.params.chatId;

    const success = await MessageModel.markAsRead(chatId, userId);

    if (!success) {
      res.status(400).json({ error: 'Failed to mark as read' });
      return;
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to mark as read' });
  }
});

export default router;
