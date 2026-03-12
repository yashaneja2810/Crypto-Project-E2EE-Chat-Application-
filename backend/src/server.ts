import express, { Application } from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { setupSocketIO } from './socket';
import { logger } from './utils/logger';
import { errorHandler } from './middleware/errorHandler';
import { rateLimiter } from './middleware/rateLimiter';

// Import routes
import authRoutes from './routes/auth.routes';
import userRoutes from './routes/user.routes';
import friendRoutes from './routes/friend.routes';
import chatRoutes from './routes/chat.routes';
import groupRoutes from './routes/group.routes';
import messageRoutes from './routes/message.routes';
import deviceRoutes from './routes/device.routes';
import { keysRouter } from './routes/keys.routes';
import { prekeysRouter } from './routes/prekeys.routes';

// Load environment variables
dotenv.config();

const app: Application = express();
const httpServer = createServer(app);

// TEMPORARY: Allow all origins to fix immediate CORS issue
// TODO: Restrict to specific origins after confirming deployment works
const productionUrl = 'https://social-media-application-zeta.vercel.app';
const allowedOrigins: string[] = process.env.NODE_ENV === 'production'
  ? [productionUrl]
  : ['http://localhost:5173', 'http://127.0.0.1:5173'];

logger.info(`Environment: ${process.env.NODE_ENV}`);
logger.info(`CORS allowed origins: ${allowedOrigins.join(', ')}`);

const io = new SocketIOServer(httpServer, {
  cors: {
    origin: '*', // Temporary fix - allow all origins for Socket.IO
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

// Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// TEMPORARY: Allow all origins
app.use(cors({
  origin: true, // Accept any origin temporarily
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204,
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(rateLimiter);

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/friends', friendRoutes);
app.use('/api/chats', chatRoutes);
app.use('/api/groups', groupRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/keys', keysRouter);
app.use('/api/prekeys', prekeysRouter);

// Setup WebSocket
setupSocketIO(io);

// Error handling
app.use(errorHandler);

const PORT = process.env.PORT || 3000;

httpServer.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

export { io };
