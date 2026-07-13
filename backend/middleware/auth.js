// ──────────────────────────────────────────────────────────
//  NetGuard Cloud Platform – Authentication Middleware
//  Supports: JWT Token + Session auth
// ──────────────────────────────────────────────────────────
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// JWT Token Auth (for frontend & extension)
exports.authenticate = async (req, res, next) => {
  try {
    // Try JWT token first
    const token = req.headers.authorization?.split(' ')[1] ||
                  req.headers['x-auth-token'];

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        issuer: 'netguard-api', audience: 'netguard-client',
      });
      req.user = await User.findById(decoded.id).select('-password');
      if (req.user) return next();
    }

    // Fallback to session auth
    if (req.session && req.session.passport && req.session.passport.user) {
      req.user = await User.findById(req.session.passport.user).select('-password');
      if (req.user) return next();
    }

    res.status(401).json({ success: false, message: 'Authentication required' });
  } catch (error) {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

// Check if user is authenticated (session-based)
exports.isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  // Also accept JWT
  if (req.headers.authorization) {
    return exports.authenticate(req, res, next);
  }
  res.status(401).json({ success: false, message: 'Please log in' });
};

// Check if user is admin
exports.isAdmin = async (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    return next();
  }
  res.status(403).json({ success: false, message: 'Admin access required' });
};

// JWT auth for extension API
exports.extensionAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'netguard-api', audience: 'netguard-client',
    });
    req.extensionUser = decoded;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
};
