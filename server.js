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
// Admin configuration with logging
// ----------------------------------------------------------------------
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim());
console.log('👑 Admin emails from env:', ADMIN_EMAILS);
console.log('👑 Raw ADMIN_EMAILS env:', process.env.ADMIN_EMAILS);

// ----------------------------------------------------------------------
// Environment logs
// ----------------------------------------------------------------------
console.log('🔍 GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? '✅ set' : '❌ MISSING');
console.log('🔍 GOOGLE_CLIENT_SECRET (first 4 chars):', 
    process.env.GOOGLE_CLIENT_SECRET ? process.env.GOOGLE_CLIENT_SECRET.substring(0,4) : '❌ MISSING');
console.log('🔍 SESSION_SECRET (first 4 chars):', 
    process.env.SESSION_SECRET ? process.env.SESSION_SECRET.substring(0,4) : '❌ MISSING');

// ----------------------------------------------------------------------
// Session configuration
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

// Body parsers
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/webhook', bodyParser.raw({ type: '*/*' }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ----------------------------------------------------------------------
// Passport serialization
// ----------------------------------------------------------------------
passport.serializeUser((user, done) => {
    console.log('Serializing user:', user.id);
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    console.log('Deserializing user:', id);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    if (user) {
        console.log('Deserialized user email:', user.email);
        console.log('Admin check:', ADMIN_EMAILS.includes(user.email));
        user.isAdmin = ADMIN_EMAILS.includes(user.email);
    }
    done(null, user);
});

// ----------------------------------------------------------------------
// Google Strategy – store email with debug
// ----------------------------------------------------------------------
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'https://webhooks-gwsp.onrender.com/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    console.log('✅ Google strategy verify function called');
    console.log('Profile ID:', profile.id);
    console.log('Email:', profile.emails?.[0]?.value);
    console.log('Full profile:', JSON.stringify(profile, null, 2));
    
    try {
      let user = db.prepare('SELECT * FROM users WHERE id = ?').get(profile.id);
      const email = profile.emails?.[0]?.value || null;
      if (!user) {
        console.log('🆕 New user, inserting into database');
        const stmt = db.prepare(`
          INSERT INTO users (id, username, avatar, email, provider)
          VALUES (?, ?, ?, ?, 'google')
        `);
        stmt.run(profile.id, profile.displayName, profile.photos[0]?.value, email);
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(profile.id);
      } else {
        console.log('🔄 Existing user, updating avatar and email');
        db.prepare('UPDATE users SET avatar = ?, email = ? WHERE id = ?').run(profile.photos[0]?.value, email, profile.id);
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(profile.id);
      }
      console.log('User after upsert:', user);
      // Add isAdmin flag
      user.isAdmin = ADMIN_EMAILS.includes(user.email);
      console.log('isAdmin set to:', user.isAdmin);
      return done(null, user);
    } catch (err) {
      console.error('❌ Database error:', err);
      return done(err);
    }
  }
));

// ----------------------------------------------------------------------
// Middleware
// ----------------------------------------------------------------------
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/');
}

function ensureAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.isAdmin) {
        return next();
    }
    console.log('Admin access denied. User:', req.user);
    res.status(403).send('Forbidden: Admins only');
}

// ----------------------------------------------------------------------
// Routes
// ----------------------------------------------------------------------

// Home
app.get('/', (req, res) => {
    console.log('Home route, isAuthenticated:', req.isAuthenticated());
    if (req.isAuthenticated()) {
        // Ensure isAdmin flag is set
        req.user.isAdmin = ADMIN_EMAILS.includes(req.user.email);
        console.log('Home route user:', { id: req.user.id, email: req.user.email, isAdmin: req.user.isAdmin });
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
app.get('/choose-username', ensureAuthenticated, (req, res) => {
    res.render('choose-username', { user: req.user });
});

app.post('/choose-username', ensureAuthenticated, (req, res) => {
    console.log('POST /choose-username body:', req.body);
    const { username } = req.body;
    console.log('Username received:', username);
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

// Delete a webhook key (protected)
app.post('/delete-key/:key', ensureAuthenticated, (req, res) => {
    const { key } = req.params;
    const keyOwner = db.prepare('SELECT user_id FROM webhook_keys WHERE key = ?').get(key);
    if (!keyOwner || keyOwner.user_id !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const deleteRequests = db.prepare('DELETE FROM webhook_requests WHERE key = ?');
    deleteRequests.run(key);
    const deleteKey = db.prepare('DELETE FROM webhook_keys WHERE key = ?');
    deleteKey.run(key);
    res.json({ success: true });
});

// ----------------------------------------------------------------------
// Admin routes
// ----------------------------------------------------------------------

// Admin dashboard
app.get('/admin', ensureAdmin, (req, res) => {
    const totalKeys = db.prepare('SELECT COUNT(*) as count FROM webhook_keys').get();
    const keys = db.prepare(`
        SELECT wk.key, wk.created_at, u.username, u.email, u.chosen_username
        FROM webhook_keys wk
        JOIN users u ON wk.user_id = u.id
        ORDER BY wk.created_at DESC
    `).all();
    res.render('admin', { user: req.user, totalKeys: totalKeys.count, keys });
});

// Admin view of any webhook key's logs
app.get('/admin/view/:key', ensureAdmin, (req, res) => {
    const { key } = req.params;
    const keyExists = db.prepare('SELECT key FROM webhook_keys WHERE key = ?').get(key);
    if (!keyExists) {
        return res.status(404).send('Webhook key not found');
    }
    const requests = db.prepare(`
        SELECT method, headers, body, timestamp
        FROM webhook_requests
        WHERE key = ?
        ORDER BY timestamp DESC
    `).all(key);
    // Reuse the existing view-key.ejs, but pass a flag to hide delete buttons
    res.render('view-key', { key, requests, user: req.user, isAdminView: true });
});

// Webhook tester page
app.get('/admin/tester', ensureAdmin, (req, res) => {
    res.render('tester', { user: req.user });
});

// Proxy endpoint for webhook tester (to avoid CORS)
app.post('/admin/proxy', ensureAdmin, express.json(), async (req, res) => {
    const { method, url, body } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'URL required' });
    }
    try {
        const fetchOptions = {
            method: method,
            headers: { 'Content-Type': 'application/json' },
        };
        if (body && (method === 'POST' || method === 'PATCH')) {
            fetchOptions.body = body;
        }
        const response = await fetch(url, fetchOptions);
        const responseText = await response.text();
        res.json({
            status: response.status,
            statusText: response.statusText,
            headers: Object.fromEntries(response.headers.entries()),
            body: responseText
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ----------------------------------------------------------------------
// Debug route to check your user (remove after fixing)
// ----------------------------------------------------------------------
app.get('/debug-me', ensureAuthenticated, (req, res) => {
    res.json({
        id: req.user.id,
        email: req.user.email,
        username: req.user.username,
        chosen_username: req.user.chosen_username,
        isAdmin: req.user.isAdmin,
        adminList: ADMIN_EMAILS
    });
});

// ----------------------------------------------------------------------
// Database check and start
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
