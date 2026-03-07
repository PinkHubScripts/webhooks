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
console.log('🔍 SESSION_SECRET (first 4 chars):', 
    process.env.SESSION_SECRET ? process.env.SESSION_SECRET.substring(0,4) : '❌ MISSING');

// ----------------------------------------------------------------------
// 1. Session
// ----------------------------------------------------------------------
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
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
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
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
    try {
      // Check if user exists
      let user = db.prepare('SELECT * FROM users WHERE id = ?').get(profile.id);
      if (!user) {
        // New user – insert
        const stmt = db.prepare(`
          INSERT INTO users (id, username, avatar, provider)
          VALUES (?, ?, ?, 'google')
        `);
        stmt.run(profile.id, profile.displayName, profile.photos[0]?.value);
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(profile.id);
        console.log('🆕 New Google user created:', user);
      } else {
        // Update avatar
        db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(profile.photos[0]?.value, profile.id);
        // Refresh user data
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(profile.id);
        console.log('🔄 Existing Google user logged in:', user);
      }
      return done(null, user);
    } catch (err) {
      console.error('Google auth error:', err);
      return done(err);
    }
  }
));

// ----------------------------------------------------------------------
// 4. Discord placeholder (avoids rate limits)
// ----------------------------------------------------------------------
app.get('/auth/discord', (req, res) => {
    res.send('Discord login is temporarily unavailable. Please use Google.');
});

// ----------------------------------------------------------------------
// 5. Routes
// ----------------------------------------------------------------------

// Home
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        const keys = db.prepare('SELECT * FROM webhook_keys WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
        res.render('index', { user: req.user, keys });
    } else {
        res.render('index', { user: null, keys: [] });
    }
});

// Google login
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google callback – with detailed logging
app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        console.log('✅ Google callback successful. User:', req.user);
        console.log('chosen_username =', req.user.chosen_username);
        if (!req.user.chosen_username) {
            console.log('➡️ Redirecting to /choose-username');
            res.redirect('/choose-username');
        } else {
            console.log('➡️ Redirecting to home (username already set)');
            res.redirect('/');
        }
    }
);

// Username selection page
app.get('/choose-username', ensureAuthenticated, (req, res) => {
    res.render('choose-username', { user: req.user });
});

app.post('/choose-username', ensureAuthenticated, (req, res) => {
    const { username } = req.body;
    if (!username || username.length < 3) {
        return res.render('choose-username', { user: req.user, error: 'Username must be at least 3 characters.' });
    }
    db.prepare('UPDATE users SET chosen_username = ? WHERE id = ?').run(username, req.user.id);
    // Update session user
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

// API endpoint
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
// 6. Auth middleware
// ----------------------------------------------------------------------
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/');
}

// ----------------------------------------------------------------------
// 7. DB test
// ----------------------------------------------------------------------
try {
    db.prepare('SELECT 1').get();
    console.log('✅ Database connected');
} catch (err) {
    console.error('❌ Database connection error:', err);
    process.exit(1);
}

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
