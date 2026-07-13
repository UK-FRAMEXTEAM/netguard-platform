const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const User = require('../models/User');

function normalizeEmail(value = '') {
  return value.trim().toLowerCase();
}

module.exports = function configurePassport(passport) {
  const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL } = process.env;

  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_CALLBACK_URL) {
    console.warn('[auth] Google OAuth is disabled until GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_CALLBACK_URL are configured.');
    return false;
  }

  passport.use(new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: GOOGLE_CALLBACK_URL,
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = normalizeEmail(profile.emails?.[0]?.value);
        if (!email) return done(new Error('Google account did not provide an email address'));

        const adminEmail = normalizeEmail(process.env.ADMIN_EMAIL);
        let user = await User.findOne({ $or: [{ googleId: profile.id }, { email }] });

        if (!user) {
          user = await User.create({
            googleId: profile.id,
            name: profile.displayName || email.split('@')[0],
            email,
            avatar: profile.photos?.[0]?.value,
            role: email === adminEmail ? 'admin' : 'user',
            authProvider: 'google',
            lastLogin: new Date(),
          });
        } else {
          user.googleId = profile.id;
          user.name = profile.displayName || user.name;
          user.avatar = profile.photos?.[0]?.value || user.avatar;
          user.authProvider = user.password ? 'local+google' : 'google';
          if (email === adminEmail) user.role = 'admin';
          user.lastLogin = new Date();
          await user.save();
        }

        done(null, user);
      } catch (error) {
        done(error);
      }
    }
  ));

  return true;
};
