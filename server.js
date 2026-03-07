require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const db = require('./db'); // SQLite database (kept for now)
const fetch = require('node-fetch'); // For manual token exchange

const app = express();
const PORT = process.env.PORT || 3000;

// ----------------------------------------------------------------------
// 0. Log environment variables (safe, only first few chars)
// ----------------------------------------------------------------------
console.log('🔍 DISCORD_CLIENT_ID:', process.env.DISCORD_CLIENT_ID);
console.log('🔍 DISCORD_CLIENT_SECRET (first 4 chars):', 
    process.env.DISCORD_CLIENT_SECRET ? process.env.DISCORD_CLIENT_SECRET.substring(0,4) : '❌ MISSING');
console.log('🔍 SESSION_SECRET (first 4 chars):', 
    process.env.SESSION_SECRET ? process.env.SESSION_SECRET.substring(0,4) : '❌ MISSING');
console.log('🔍 NODE_ENV:', process.env.NODE_ENV);

// ----------------------------------------------------------------------
// 1. Session configuration (MemoryStore warning is safe to ignore for now)
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
// 2. Passport serialization (we still need this for session handling)
// ----------------------------------------------------------------------
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    done(null, user);
});

// ----------------------------------------------------------------------
// 3. Manual OAuth callback – NO passport.authenticate here
// ----------------------------------------------------------------------
const DISCORD_CALLBACK_URL = 'https://webhooks-gwsp.onrender.com/auth/discord/callback';

app.get('/auth/discord/callback', (req, res) => {
    console.log('📞 Callback reached at', new Date().toISOString());
    console.log('Query params:', req.query);
    
    const { code, error } = req.query;
    if (error) {
        console.error('Discord returned error:', error);
        return res.status(400).send('Discord error: ' + error);
    }
    if (!code) {
        console.error('No code in callback');
        return res.status(400).send('No code provided');
    }
    console.log('✅ Authorization code received (first 10 chars):', code.substring(0, 10) + '...');

    // --- Manual token exchange ---
    const params = new URLSearchParams();
    params.append('client_id', process.env.DISCORD_CLIENT_ID);
    params.append('client_secret', process.env.DISCORD_CLIENT_SECRET);
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('redirect_uri', DISCORD_CALLBACK_URL);
    params.append('scope', 'identify email guilds');

    fetch('https://discord.com/api/oauth2/token', {
        method: 'POST',
        body: params,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    })
    .then(response => response.json())
    .then(tokenData => {
        console.log('Token exchange response keys:', Object.keys(tokenData));
        if (!tokenData.access_token) {
            throw new Error('Failed to get access token: ' + JSON.stringify(tokenData));
        }
        // Fetch user profile with the access token
        return fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
    })
    .then(response => response.json())
    .then(profile => {
        console.log(`✅ Discord login successful for ${profile.username} (${profile.id})`);
        // Save user to database
        const stmt = db.prepare(`
            INSERT OR REPLACE INTO users (id, username, avatar)
            VALUES (?, ?, ?)
        `);
        stmt.run(profile.id, profile.username, profile.avatar);
        
        // Manually log the user in via Passport
        req.login(profile, (err) => {
            if (err) {
                console.error('Login error:', err);
                return res.status(500).send('Login failed');
            }
            console.log('🎉 User logged in, redirecting to home');
            res.redirect('/');
        });
    })
    .catch(err => {
        console.error('❌ Manual token exchange error:', err);
        res.status(500).send('Authentication failed: ' + err.message);
    });
});

// ----------------------------------------------------------------------
// 4. Discord login route – redirects to Discord
// ----------------------------------------------------------------------
app.get('/auth/discord', (req, res) => {
    const discordAuthUrl = `https://discord.com/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(DISCORD_CALLBACK_URL)}&scope=identify%20email%20guilds`;
    res.redirect(discordAuthUrl);
});

// ----------------------------------------------------------------------
// 5. Logout
// ----------------------------------------------------------------------
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) console.error(err);
        res.redirect('/');
    });
});

// ----------------------------------------------------------------------
// 6. Home page
// ----------------------------------------------------------------------
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        const keys = db.prepare('SELECT * FROM webhook_keys WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
        res.render('index', { user: req.user, keys });
    } else {
        res.render('index', { user: null, keys: [] });
    }
});

// ----------------------------------------------------------------------
// 7. Webhook key generation (protected)
// ----------------------------------------------------------------------
app.post('/generate', ensureAuthenticated, (req, res) => {
    const key = crypto.randomBytes(16).toString('hex');
    const stmt = db.prepare('INSERT INTO webhook_keys (key, user_id) VALUES (?, ?)');
    stmt.run(key, req.user.id);
    res.json({ key, webhookUrl: `/webhook/${key}`, viewUrl: `/view/${key}` });
});

// ----------------------------------------------------------------------
// 8. Public webhook endpoint
// ----------------------------------------------------------------------
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

// ----------------------------------------------------------------------
// 9. View key data (protected)
// ----------------------------------------------------------------------
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

// ----------------------------------------------------------------------
// 10. API endpoint (protected)
// ----------------------------------------------------------------------
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
// 11. Authentication middleware
// ----------------------------------------------------------------------
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/');
}

// ----------------------------------------------------------------------
// 12. Test database connection
// ----------------------------------------------------------------------
try {
    db.prepare('SELECT 1').get();
    console.log('✅ Database connected');
} catch (err) {
    console.error('❌ Database connection error:', err);
    process.exit(1);
}

// ----------------------------------------------------------------------
// 13. Start server
// ----------------------------------------------------------------------
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
