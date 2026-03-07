require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// ----------------------------------------------------------------------
// 0. Environment logs
// ----------------------------------------------------------------------
console.log('🔍 GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? '✅ set' : '❌ MISSING');
console.log('🔍 GOOGLE_CLIENT_SECRET (first 4 chars):', 
    process.env.GOOGLE_CLIENT_SECRET ? process.env.GOOGLE_CLIENT_SECRET.substring(0,4) : '❌ MISSING');
console.log('🔍 SESSION_SECRET (first 4 chars):', 
    process.env.SESSION_SECRET ? process.env.SESSION_SECRET.substring(0,4) : '❌ MISSING');

// ----------------------------------------------------------------------
// 1. Session configuration – fixed for production with proxy
// ----------------------------------------------------------------------
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // true on Render (HTTPS)
        sameSite: 'lax', // prevents cross-site issues
        maxAge: 24 * 60 * 60 * 1000 // 1 day (optional)
    },
    proxy: true // trust the reverse proxy (Render)
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.raw({ type: '*/*' }));
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ----------------------------------------------------------------------
// 2. Passport serialization
// ----------------------------------------------------------------------
passport.serializeUser((user, done) => {
    console.log('Serializing user:', user.id);
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    console.log('Deserializing user:', id);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    done(null, user);
});

// ----------------------------------------------------------------------
// 3. Google Strategy
// ----------------------------------------------------------------------
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'https://webhooks-gwsp.onrender.com/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    console.log('✅ Google strategy verify function called');
    console.log('Profile ID:', profile.id);
    
    try {
      let user = db.prepare('SELECT * FROM users WHERE id = ?').get(profile.id);
      if (!user) {
        console.log('🆕 New user, inserting into database');
        const stmt = db.prepare(`
          INSERT INTO users (id, username, avatar, provider)
          VALUES (?, ?, ?, 'google')
        `);
        stmt.run(profile.id, profile.displayName, profile.photos[0]?.value);
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(profile.id);
      } else {
        console.log('🔄 Existing user, updating avatar');
        db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(profile.photos[0]?.value, profile.id);
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(profile.id);
      }
      return done(null, user);
    } catch (err) {
      console.error('❌ Database error:', err);
      return done(err);
    }
  }
));

// ----------------------------------------------------------------------
// 4. Routes
// ----------------------------------------------------------------------

// Home
app.get('/', (req, res) => {
    console.log('Home route, isAuthenticated:', req.isAuthenticated());
    if (req.isAuthenticated()) {
        const keys = db.prepare('SELECT * FROM webhook_keys WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
        res.render('index', { user: req.user, keys });
    } else {
        res.render('index', { user: null, keys: [] });
    }
});

// Google login
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google callback
app.get('/auth/google/callback', 
    (req, res, next) => {
        console.log('📞 Google callback reached');
        console.log('Query:', req.query);
        if (req.query.error) {
            console.error('Google error:', req.query.error);
            return res.status(400).send('Google error: ' + req.query.error);
        }
        next();
    },
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        console.log('✅ Google authentication successful, user:', req.user.id);
        if (!req.user.chosen_username) {
            console.log('➡️ Redirecting to /choose-username');
            res.redirect('/choose-username');
        } else {
            console.log('➡️ Redirecting to home');
            res.redirect('/');
        }
    }
);

// Username selection – with auth check log
app.get('/choose-username', (req, res, next) => {
    console.log('/choose-username route, isAuthenticated:', req.isAuthenticated());
    if (!req.isAuthenticated()) {
        console.log('Not authenticated, redirecting to home');
        return res.redirect('/');
    }
    next();
}, (req, res) => {
    res.render('choose-username', { user: req.user });
});

app.post('/choose-username', ensureAuthenticated, (req, res) => {
    const { username } = req.body;
    if (!username || username.length < 3) {
        return res.render('choose-username', { user: req.user, error: 'Username must be at least 3 characters.' });
    }
    db.prepare('UPDATE users SET chosen_username = ? WHERE id = ?').run(username, req.user.id);
    req.user.chosen_username = username;
    console.log(`✅ Username set to "${username}" for user ${req.user.id}`);
    res.redirect('/');
});

// Logout
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) console.error(err);
        res.redirect('/');
    });
});

// Discord placeholder
app.get('/auth/discord', (req, res) => {
    res.send('Discord login is temporarily unavailable. Please use Google.');
});

// Webhook generation (protected)
app.post('/generate', ensureAuthenticated, (req, res) => {
    const key = crypto.randomBytes(16).toString('hex');
    const stmt = db.prepare('INSERT INTO webhook_keys (key, user_id) VALUES (?, ?)');
    stmt.run(key, req.user.id);
    res.json({ key, webhookUrl: `/webhook/${key}`, viewUrl: `/view/${key}` });
});

// Public webhook endpoint
app.all('/webhook/:key', (req, res) => {
    const { key } = req.params;
    const keyExists = db.prepare('SELECT key FROM webhook_keys WHERE key = ?').get(key);
    if (!keyExists) {
        return res.status(404).send('Webhook key not found');
    }
    const stmt = db.prepare(`
        INSERT INTO webhook_requests (key, method, headers, body)
        VALUES (?, ?, ?, ?)
    `);
    stmt.run(
        key,
        req.method,
        JSON.stringify(req.headers),
        req.body.toString('utf8')
    );
    res.status(200).send('Webhook received');
});

// View key data (protected)
app.get('/view/:key', ensureAuthenticated, (req, res) => {
    const { key } = req.params;
    const keyOwner = db.prepare('SELECT user_id FROM webhook_keys WHERE key = ?').get(key);
    if (!keyOwner || keyOwner.user_id !== req.user.id) {
        return res.status(403).send('Forbidden');
    }
    const requests = db.prepare(`
        SELECT method, headers, body, timestamp
        FROM webhook_requests
        WHERE key = ?
        ORDER BY timestamp DESC
    `).all(key);
    res.render('view-key', { key, requests, user: req.user });
});

// API endpoint (protected)
app.get('/api/webhook/:key', ensureAuthenticated, (req, res) => {
    const { key } = req.params;
    const keyOwner = db.prepare('SELECT user_id FROM webhook_keys WHERE key = ?').get(key);
    if (!keyOwner || keyOwner.user_id !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const requests = db.prepare('SELECT * FROM webhook_requests WHERE key = ? ORDER BY timestamp DESC').all(key);
    res.json(requests);
});

// ----------------------------------------------------------------------
// 5. Auth middleware
// ----------------------------------------------------------------------
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/');
}

// ----------------------------------------------------------------------
// 6. Database check
// ----------------------------------------------------------------------
try {
    db.prepare('SELECT 1').get();
    console.log('✅ Database connected');
} catch (err) {
    console.error('❌ Database connection error:', err);
    process.exit(1);
}

// ----------------------------------------------------------------------
// 7. Start server
// ----------------------------------------------------------------------
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
