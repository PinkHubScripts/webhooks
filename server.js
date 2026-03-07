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
// 1. Session configuration – fixed for production
// ----------------------------------------------------------------------
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000
    },
    proxy: true
}));

app.use(passport.initialize());
app.use(passport.session());

// ----------------------------------------------------------------------
// 2. Body parsers – IMPORTANT: raw only for webhooks, urlencoded for forms
// ----------------------------------------------------------------------
// Parse application/x-www-form-urlencoded (for username form)
app.use(express.urlencoded({ extended: true }));

// Parse JSON (if you ever need it – optional)
app.use(express.json());

// Raw body parser – apply ONLY to /webhook/* routes (after urlencoded/json)
app.use('/webhook', bodyParser.raw({ type: '*/*' }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ----------------------------------------------------------------------
// 3. Passport serialization
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
// 4. Google Strategy
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
// 5. Routes
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

// Username selection
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
    console.log('POST /choose-username body:', req.body);
    const { username } = req.body;
    console.log('Username received:', username);
    if (!username || username.length < 3) {
        console.log('Validation failed: username length =', username ? username.length : 'null');
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

// Public webhook endpoint – now uses raw body parser (mounted earlier)
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
        req.body.toString('utf8') // req.body is a Buffer thanks to the raw middleware
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
// 6. Auth middleware
// ----------------------------------------------------------------------
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/');
}

// ----------------------------------------------------------------------
// 7. Database check
// ----------------------------------------------------------------------
try {
    db.prepare('SELECT 1').get();
    console.log('✅ Database connected');
} catch (err) {
    console.error('❌ Database connection error:', err);
    process.exit(1);
}

// ----------------------------------------------------------------------
// 8. Start server
// ----------------------------------------------------------------------
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
