require('dotenv').config();
const express = require('express');
const passport = require('passport');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/db');

const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const adminRoutes = require('./routes/admin');
const extensionRoutes = require('./routes/api');
const publicRoutes = require('./routes/public');
const assistantRoutes = require('./routes/assistant');

const required = ['MONGODB_URI', 'JWT_SECRET'];
const missing = required.filter((name) => !process.env[name]);
if (missing.length) {
  throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
}

const app = express();
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

const configuredOrigins = (process.env.CORS_ORIGINS || process.env.FRONTEND_URL || '')
  .split(',')
  .map((value) => value.trim().replace(/\/$/, ''))
  .filter(Boolean);
const allowedOrigins = new Set([
  'http://localhost:5173',
  'http://localhost:3000',
  ...configuredOrigins,
]);

app.use(cors({
  origin(origin, callback) {
    const isChromeExtension = origin?.startsWith('chrome-extension://');
    if (!origin || allowedOrigins.has(origin) || isChromeExtension) return callback(null, true);
    return callback(new Error('Origin is not allowed by CORS'));
  },
  credentials: false,
}));

// The assistant accepts one transient base64 screenshot up to 4 MB.
app.use(express.json({ limit: '6mb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(passport.initialize());
const googleOAuthEnabled = require('./config/passport')(passport);
app.locals.googleOAuthEnabled = googleOAuthEnabled;

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: process.env.NODE_ENV === 'production' ? 300 : 1000,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests; please try again later.' },
});
app.use('/api', apiLimiter);

app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/extension', extensionRoutes);
app.use('/api/public', publicRoutes);
app.use('/api/assistant', assistantRoutes);

app.get('/api/health', (_req, res) => {
  res.json({
    success: true,
    message: 'NetGuard API is running',
    version: '3.2.0',
    googleOAuth: googleOAuthEnabled,
    geminiAssistant: Boolean(process.env.GEMINI_API_KEY),
    timestamp: new Date().toISOString(),
  });
});

app.use((error, _req, res, _next) => {
  console.error('[server]', error.message);
  res.status(error.message.includes('CORS') ? 403 : 500).json({
    success: false,
    message: error.message.includes('CORS') ? 'Origin is not allowed' : 'Unexpected server error',
  });
});

const PORT = Number(process.env.PORT) || 5000;
connectDB()
  .then(() => app.listen(PORT, '0.0.0.0', () => {
    console.log(`[server] NetGuard API v3.2.0 listening on ${PORT}`);
  }))
  .catch((error) => {
    console.error('[server] Database connection failed:', error.message);
    process.exit(1);
  });

module.exports = app;
