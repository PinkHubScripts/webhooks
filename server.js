require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');

// ----------------------------------------------------------------------
// 0. Log environment variables (safe, only first few chars)
// ----------------------------------------------------------------------
console.log('🔍 DISCORD_CLIENT_ID:', process.env.DISCORD_CLIENT_ID);
console.log('🔍 DISCORD_CLIENT_SECRET (first 4 chars):', 
    process.env.DISCORD_CLIENT_SECRET ? process.env.DISCORD_CLIENT_SECRET.substring(0,4) : '❌ MISSING');
console.log('🔍 SESSION_SECRET (first 4 chars):', 
    process.env.SESSION_SECRET ? process.env.SESSION_SECRET.substring(0,4) : '❌ MISSING');
console.log('🔍 NODE_ENV:', process.env.NODE_ENV);

const app = express();
const PORT = process.env.PORT || 3000;

// ----------------------------------------------------------------------
// 1. Session configuration
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
    scope: ['identify', 'email', 'guilds']
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
// 4. Callback route with logging
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
    
    // ------------------------------------------------------------------
    // OPTIONAL: MANUAL TOKEN EXCHANGE (uncomment if Passport continues to fail)
    // ------------------------------------------------------------------
    /*
    const fetch = require('node-fetch'); // You'll need to install node-fetch
    const params = new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: req.query.code,
        redirect_uri: DISCORD_CALLBACK_URL,
        scope: 'identify email guilds'
    });

    fetch('https://discord.com/api/oauth2/token', {
        method: 'POST',
        body: params,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    })
    .then(res => res.json())
    .then(data => {
        console.log('Token exchange response:', data);
        if (data.access_token) {
            // Now fetch user profile using the access token
            return fetch('https://discord.com/api/users/@me', {
                headers: { Authorization: `Bearer ${data.access_token}` }
            });
        } else {
            throw new Error('No access token: ' + JSON.stringify(data));
        }
    })
    .then(res => res.json())
    .then(profile => {
        console.log('User profile:', profile);
        // Save user to database (similar to above)
        const stmt = db.prepare(`
            INSERT OR REPLACE INTO users (id, username, avatar)
            VALUES (?, ?, ?)
        `);
        stmt.run(profile.id, profile.username, profile.avatar);
        // Manually log the user in
        req.login(profile, (err) => {
            if (err) return next(err);
            res.redirect('/');
        });
    })
    .catch(err => {
        console.error('Manual token exchange error:', err);
        res.status(500).send('Authentication failed');
    });
    */
    // ------------------------------------------------------------------
    // If using manual, comment out the next() call below
    // ------------------------------------------------------------------
    
    // Continue to passport for now
    next();
}, passport.authenticate('discord', { failureRedirect: '/' }), (req, res) => {
    console.log('🎉 Passport authentication successful, redirecting to home');
    res.redirect('/');
});

// ----------------------------------------------------------------------
// 5. Other routes (home, login, logout, generate, webhook, view, etc.)
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

app.get('/auth/discord', passport.authenticate('discord'));

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) console.error(err);
        res.redirect('/');
    });
});

app.post('/generate', ensureAuthenticated, (req, res) => {
    const key = crypto.randomBytes(16).toString('hex');
    const stmt = db.prepare('INSERT INTO webhook_keys (key, user_id) VALUES (?, ?)');
    stmt.run(key, req.user.id);
    res.json({ key, webhookUrl: `/webhook/${key}`, viewUrl: `/view/${key}` });
});

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

app.get('/api/webhook/:key', ensureAuthenticated, (req, res) => {
    const { key } = req.params;
    const keyOwner = db.prepare('SELECT user_id FROM webhook_keys WHERE key = ?').get(key);
    if (!keyOwner || keyOwner.user_id !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const requests = db.prepare('SELECT * FROM webhook_requests WHERE key = ? ORDER BY timestamp DESC').all(key);
    res.json(requests);
});

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/');
}

// ----------------------------------------------------------------------
// 6. Test database connection
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
