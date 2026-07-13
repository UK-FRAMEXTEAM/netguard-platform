const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/User');

const router = express.Router();

function normalizeEmail(value = '') {
  return value.trim().toLowerCase();
}

function signToken(user) {
  return jwt.sign(
    { id: user._id.toString(), email: user.email, role: user.role, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: '7d', issuer: 'netguard-api', audience: 'netguard-client' }
  );
}

function publicUser(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    avatar: user.avatar,
    role: user.role,
    authProvider: user.authProvider,
  };
}

function cookieValue(req, name) {
  const cookie = String(req.headers.cookie || '')
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  if (!cookie) return null;
  try { return decodeURIComponent(cookie.slice(name.length + 1)); }
  catch { return null; }
}

function safeEqual(left, right) {
  if (!left || !right) return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

router.post('/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    if (name.length > 80 || !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ success: false, message: 'Enter a valid name and email address' });
    }
    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({ success: false, message: 'Password must be 8-128 characters' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      const message = existing.password ? 'An account already exists for this email' : 'Use Continue with Google for this email';
      return res.status(409).json({ success: false, message });
    }

    const adminEmail = normalizeEmail(process.env.ADMIN_EMAIL);
    const user = await User.create({
      name,
      email,
      password: await bcrypt.hash(password, 12),
      authProvider: 'local',
      role: email === adminEmail ? 'admin' : 'user',
      lastLogin: new Date(),
    });

    res.status(201).json({ success: true, user: publicUser(user), token: signToken(user) });
  } catch (error) {
    console.error('[auth/register]', error.message);
    res.status(500).json({ success: false, message: 'Registration failed' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user || !user.password) {
      const message = user ? 'This account uses Google sign-in' : 'Invalid email or password';
      return res.status(401).json({ success: false, message });
    }
    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    const adminEmail = normalizeEmail(process.env.ADMIN_EMAIL);
    user.role = email === adminEmail ? 'admin' : 'user';
    user.lastLogin = new Date();
    await user.save();
    res.json({ success: true, user: publicUser(user), token: signToken(user) });
  } catch (error) {
    console.error('[auth/login]', error.message);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

router.get('/google', (req, res, next) => {
  if (!req.app.locals.googleOAuthEnabled) {
    return res.status(503).json({ success: false, message: 'Google sign-in is not configured yet' });
  }
  const state = crypto.randomBytes(32).toString('base64url');
  res.cookie('ng_oauth_state', state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 10 * 60 * 1000,
    path: '/api/auth/google',
  });
  return passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false,
    prompt: 'select_account',
    state,
  })(req, res, next);
});

router.get(
  '/google/callback',
  (req, res, next) => {
    const expected = cookieValue(req, 'ng_oauth_state');
    res.clearCookie('ng_oauth_state', { path: '/api/auth/google' });
    if (!safeEqual(expected, req.query.state)) {
      const frontendUrl = String(process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
      return res.redirect(`${frontendUrl}/login?error=invalid_oauth_state`);
    }
    return next();
  },
  (req, res, next) => {
    if (!req.app.locals.googleOAuthEnabled) return res.redirect(`${process.env.FRONTEND_URL}/login?error=google_not_configured`);
    return passport.authenticate('google', { session: false, failureRedirect: '/api/auth/google/failure' })(req, res, next);
  },
  (req, res) => {
    const frontendUrl = String(process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
    const token = signToken(req.user);
    res.redirect(`${frontendUrl}/auth/callback#token=${encodeURIComponent(token)}`);
  }
);

router.get('/google/failure', (_req, res) => {
  const frontendUrl = String(process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
  res.redirect(`${frontendUrl}/login?error=google_auth_failed`);
});

router.get('/me', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.headers['x-auth-token'];
    if (!token) return res.status(401).json({ success: false, message: 'Authentication required' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'netguard-api',
      audience: 'netguard-client',
    });
    const user = await User.findById(decoded.id).select('-password -googleId');
    if (!user) return res.status(401).json({ success: false, message: 'User not found' });
    const expectedRole = normalizeEmail(user.email) === normalizeEmail(process.env.ADMIN_EMAIL) ? 'admin' : 'user';
    if (user.role !== expectedRole) {
      user.role = expectedRole;
      await user.save();
    }
    res.json({ success: true, user });
  } catch {
    res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
});

router.post('/extension-login', async (req, res) => {
  try {
    const decoded = jwt.verify(String(req.body.token || ''), process.env.JWT_SECRET, {
      issuer: 'netguard-api',
      audience: 'netguard-client',
    });
    const user = await User.findById(decoded.id).select('-password -googleId');
    if (!user) return res.status(401).json({ success: false, message: 'User not found' });
    res.json({ success: true, user });
  } catch {
    res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
});

module.exports = router;
