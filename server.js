require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const db = require('./db'); // Make sure db.js exists

const app = express();
const PORT = process.env.PORT || 3000;

// ----------------------------------------------------------------------
// 1. Session configuration (MemoryStore is fine for now)
// ----------------------------------------------------------------------
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' } // true if HTTPS
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.raw({ type: '*/*' }));
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
// 3. Discord Strategy – using absolute callback URL
// ----------------------------------------------------------------------
const DISCORD_CALLBACK_URL = 'https://webhooks-gwsp.onrender.com/auth/discord/callback';

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: DISCORD_CALLBACK_URL,
    scope: ['identify', 'email', 'guilds'] // adjust scopes as needed
}, (accessToken, refreshToken, profile, done) => {
    try {
        console.log(`✅ Discord login successful for ${profile.username} (${profile.id})`);
        const stmt = db.prepare(`
            INSERT OR REPLACE INTO users (id, username, avatar)
            VALUES (?, ?, ?)
        `);
        stmt.run(profile.id, profile.username, profile.avatar);
        return done(null, profile);
    } catch (err) {
        console.error('❌ Database error during user save:', err);
        return done(err);
    }
}));

// ----------------------------------------------------------------------
// 4. Debug OAuth errors (catches low-level token exchange errors)
// ----------------------------------------------------------------------
passport._strategies.discord._oauth2.on('error', (err) => {
    console.error('🔴 Discord OAuth2 raw error:', err);
    if (err.data) {
        console.error('Discord response body:', err.data.toString());
    }
});

// ----------------------------------------------------------------------
// 5. Manual logging route BEFORE passport handles the callback
// ----------------------------------------------------------------------
app.get('/auth/discord/callback', (req, res, next) => {
    console.log('📞 Callback reached at', new Date().toISOString());
    console.log('Query params:', req.query);
    if (req.query.error) {
        console.error('Discord returned error:', req.query.error);
        return res.status(400).send('Discord error: ' + req.query.error);
    }
    if (!req.query.code) {
        console.error('No code in callback');
        return res.status(400).send('No code provided');
    }
    console.log('✅ Authorization code received (first 10 chars):', req.query.code.substring(0, 10) + '...');
    // Continue to passport
    next();
}, passport.authenticate('discord', { failureRedirect: '/' }), (req, res) => {
    console.log('🎉 Passport authentication successful, redirecting to home');
    res.redirect('/');
});

// ----------------------------------------------------------------------
// 6. Other routes
// ----------------------------------------------------------------------

// Home page
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        const keys = db.prepare('SELECT * FROM webhook_keys WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
        res.render('index', { user: req.user, keys });
    } else {
        res.render('index', { user: null, keys: [] });
    }
});

// Discord login – starts the OAuth flow
app.get('/auth/discord', passport.authenticate('discord'));

// Logout
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) console.error(err);
        res.redirect('/');
    });
});

// Generate a new webhook key (protected)
app.post('/generate', ensureAuthenticated, (req, res) => {
    const key = crypto.randomBytes(16).toString('hex');
    const stmt = db.prepare('INSERT INTO webhook_keys (key, user_id) VALUES (?, ?)');
    stmt.run(key, req.user.id);
    res.json({ key, webhookUrl: `/webhook/${key}`, viewUrl: `/view/${key}` });
});

// Public webhook endpoint – anyone can POST to a valid key
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

// View data for a specific key (protected + ownership check)
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

    res.render('view-key', { key, requests });
});

// API endpoint for key data (protected)
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
// 7. Authentication middleware
// ----------------------------------------------------------------------
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/');
}

// ----------------------------------------------------------------------
// 8. Test database connection
// ----------------------------------------------------------------------
try {
    db.prepare('SELECT 1').get();
    console.log('✅ Database connected');
} catch (err) {
    console.error('❌ Database connection error:', err);
    process.exit(1);
}

// ----------------------------------------------------------------------
// 9. Start server
// ----------------------------------------------------------------------
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
