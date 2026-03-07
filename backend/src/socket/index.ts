import { Server as SocketIOServer, Socket } from 'socket.io';
import { supabaseAdmin } from '../config/supabase';
import { logger } from '../utils/logger';
import { SocketEvents, TypingIndicator } from '../types';
import { MessageModel } from '../models/message.model';
import { ChatModel } from '../models/chat.model';
import { UserModel } from '../models/user.model';

interface AuthenticatedSocket extends Socket {
  userId?: string;
  email?: string;
}

const connectedUsers = new Map<string, Set<string>>(); // userId -> Set of socketIds

export function setupSocketIO(io: SocketIOServer): void {
  // Socket authentication middleware
  io.use(async (socket: AuthenticatedSocket, next) => {
    try {
      const token = socket.handshake.auth.token;

      if (!token) {
        return next(new Error('Authentication token required'));
      }

      // Verify Supabase JWT
      const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);

      if (error || !user) {
        return next(new Error('Invalid authentication token'));
      }

      socket.userId = user.id;
      socket.email = user.email;

      next();
    } catch (error) {
      logger.error('Socket authentication error:', error);
      next(new Error('Authentication failed'));
    }
  });

  io.on('connection', async (socket: AuthenticatedSocket) => {
    const userId = socket.userId!;
    logger.info(`User connected: ${userId} (${socket.id})`);

    // Track connected user
    if (!connectedUsers.has(userId)) {
      connectedUsers.set(userId, new Set());
    }
    connectedUsers.get(userId)!.add(socket.id);

    // Update user status to online
    await UserModel.updateStatus(userId, 'online');

    // Join user to their personal room
    socket.join(`user:${userId}`);

    // Notify friends about online status
    await broadcastPresence(io, userId, 'online');

    // Load user's chats and join chat rooms
    const chats = await ChatModel.getUserChats(userId);
    for (const chat of chats) {
      socket.join(`chat:${chat.id}`);
    }

    // Handle message sending
    socket.on(SocketEvents.MESSAGE_SEND, async (data: {
      chatId: string;
      encryptedContent: string;
      iv?: string;  // Initialization Vector for AES-GCM
      messageType: 'text' | 'image' | 'file' | 'voice';
      metadata?: any;
      encryptionKeyId?: string;
      expiresAt?: string;
      replyTo?: string;
    }) => {
      try {
        // Verify user is in chat
        const isInChat = await ChatModel.isUserInChat(data.chatId, userId);
        if (!isInChat) {
          socket.emit(SocketEvents.ERROR, { message: 'Not authorized for this chat' });
          return;
        }

        // Create message
        const message = await MessageModel.createMessage(
          data.chatId,
          userId,
          data.encryptedContent,
          data.messageType,
          { ...data.metadata, iv: data.iv },  // Store IV in metadata
          data.encryptionKeyId,
          data.expiresAt ? new Date(data.expiresAt) : undefined,
          data.replyTo
        );

        if (message) {
          // Broadcast to chat room (including IV for decryption)
          io.to(`chat:${data.chatId}`).emit(SocketEvents.MESSAGE_RECEIVE, {
            ...message,
            iv: data.iv,  // Include IV in the broadcast
          });
        }
      } catch (error) {
        logger.error('Error sending message:', error);
        socket.emit(SocketEvents.ERROR, { message: 'Failed to send message' });
      }
    });

    // Handle message delivered acknowledgment
    socket.on(SocketEvents.MESSAGE_DELIVERED, async (data: { messageId: string }) => {
      try {
        await MessageModel.updateMessageStatus(data.messageId, 'delivered');
        
        // Notify sender - requires fetching message to get sender_id
        // TODO: Implement sender notification
      } catch (error) {
        logger.error('Error updating message delivery:', error);
      }
    });

    // Handle message read acknowledgment
    socket.on(SocketEvents.MESSAGE_READ, async (data: { chatId: string }) => {
      try {
        await MessageModel.markAsRead(data.chatId, userId);
        
        // Broadcast read status to chat
        io.to(`chat:${data.chatId}`).emit(SocketEvents.MESSAGE_READ, {
          chatId: data.chatId,
          userId,
          timestamp: new Date(),
        });
      } catch (error) {
        logger.error('Error marking messages as read:', error);
      }
    });

    // Handle typing indicators
    socket.on(SocketEvents.TYPING_START, async (data: { chatId: string }) => {
      try {
        const typingData: TypingIndicator = {
          userId,
          chatId: data.chatId,
          isTyping: true,
        };

        // Broadcast to others in chat (exclude sender)
        socket.to(`chat:${data.chatId}`).emit(SocketEvents.TYPING_UPDATE, typingData);
      } catch (error) {
        logger.error('Error handling typing start:', error);
      }
    });

    socket.on(SocketEvents.TYPING_STOP, async (data: { chatId: string }) => {
      try {
        const typingData: TypingIndicator = {
          userId,
          chatId: data.chatId,
          isTyping: false,
        };

        socket.to(`chat:${data.chatId}`).emit(SocketEvents.TYPING_UPDATE, typingData);
      } catch (error) {
        logger.error('Error handling typing stop:', error);
      }
    });

    // Handle dynamic chat room joining (for new chats created after connection)
    socket.on('chat:join', async (data: { chatId: string }) => {
      try {
        const isInChat = await ChatModel.isUserInChat(data.chatId, userId);
        if (isInChat) {
          socket.join(`chat:${data.chatId}`);
          logger.info(`User ${userId} joined chat room: ${data.chatId}`);
        }
      } catch (error) {
        logger.error('Error joining chat room:', error);
      }
    });

    // Notify recipient when a new chat is created (ECDH: no key sharing needed)
    socket.on('chat:new:notify', async (data: { chatId: string; recipientId: string }) => {
      try {
        const isInChat = await ChatModel.isUserInChat(data.chatId, userId);
        if (!isInChat) {
          socket.emit(SocketEvents.ERROR, { message: 'Not authorized' });
          return;
        }

        io.to(`user:${data.recipientId}`).emit('chat:new', {
          chatId: data.chatId,
          from: userId,
        });

        logger.info(`New chat notified: ${userId} → ${data.recipientId} for chat ${data.chatId}`);
      } catch (error) {
        logger.error('Error notifying new chat:', error);
      }
    });

    // Handle friend requests
    socket.on(SocketEvents.FRIEND_REQUEST, async (data: { friendId: string }) => {
      try {
        // Notify the friend
        io.to(`user:${data.friendId}`).emit(SocketEvents.FRIEND_REQUEST, {
          from: userId,
          timestamp: new Date(),
        });
      } catch (error) {
        logger.error('Error handling friend request:', error);
      }
    });

    // Handle disconnection
    socket.on('disconnect', async () => {
      logger.info(`User disconnected: ${userId} (${socket.id})`);

      // Remove from connected users
      const userSockets = connectedUsers.get(userId);
      if (userSockets) {
        userSockets.delete(socket.id);
        
        // If no more sockets, mark as offline
        if (userSockets.size === 0) {
          connectedUsers.delete(userId);
          await UserModel.updateStatus(userId, 'offline');
          await broadcastPresence(io, userId, 'offline');
        }
      }
    });
  });

  // Cleanup expired messages periodically
  setInterval(async () => {
    const deleted = await MessageModel.deleteExpiredMessages();
    if (deleted > 0) {
      logger.info(`Deleted ${deleted} expired messages`);
    }
  }, 60000); // Every minute
}

/**
 * Broadcast presence update to user's friends
 */
async function broadcastPresence(
  io: SocketIOServer,
  userId: string,
  status: 'online' | 'offline' | 'away'
): Promise<void> {
  // Broadcast to all connected clients (they can filter on frontend)
  io.emit(SocketEvents.PRESENCE_UPDATE, {
    userId,
    status,
    timestamp: new Date(),
  });
}

