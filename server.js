require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ----------------------------------------------------------------------
// PostgreSQL setup
// ----------------------------------------------------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Initialize tables
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT,
        avatar TEXT,
        email TEXT,
        chosen_username TEXT,
        provider TEXT DEFAULT 'google',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS webhook_keys (
        key TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS webhook_requests (
        id SERIAL PRIMARY KEY,
        key TEXT NOT NULL,
        method TEXT,
        headers TEXT,
        body TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (key) REFERENCES webhook_keys(key) ON DELETE CASCADE
      );
    `);
    console.log('✅ PostgreSQL tables ready');
  } catch (err) {
    console.error('❌ Failed to create tables:', err);
  }
})();

// ----------------------------------------------------------------------
// Admin configuration
// ----------------------------------------------------------------------
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim());
console.log('👑 Admin emails from env:', ADMIN_EMAILS);

// ----------------------------------------------------------------------
// Environment logs
// ----------------------------------------------------------------------
console.log('🔍 GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? '✅ set' : '❌ MISSING');
console.log('🔍 GOOGLE_CLIENT_SECRET (first 4 chars):', 
    process.env.GOOGLE_CLIENT_SECRET ? process.env.GOOGLE_CLIENT_SECRET.substring(0,4) : '❌ MISSING');
console.log('🔍 GITHUB_CLIENT_ID:', process.env.GITHUB_CLIENT_ID ? '✅ set' : '❌ MISSING');
console.log('🔍 GITHUB_CLIENT_SECRET (first 4 chars):', 
    process.env.GITHUB_CLIENT_SECRET ? process.env.GITHUB_CLIENT_SECRET.substring(0,4) : '❌ MISSING');
console.log('🔍 DISCORD_CLIENT_ID:', process.env.DISCORD_CLIENT_ID ? '✅ set' : '❌ MISSING');
console.log('🔍 DISCORD_CLIENT_SECRET (first 4 chars):', 
    process.env.DISCORD_CLIENT_SECRET ? process.env.DISCORD_CLIENT_SECRET.substring(0,4) : '❌ MISSING');
console.log('🔍 SESSION_SECRET (first 4 chars):', 
    process.env.SESSION_SECRET ? process.env.SESSION_SECRET.substring(0,4) : '❌ MISSING');
console.log('🔍 DATABASE_URL:', process.env.DATABASE_URL ? '✅ set' : '❌ MISSING');

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

passport.deserializeUser(async (id, done) => {
    console.log('Deserializing user:', id);
    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        const user = result.rows[0];
        if (user) {
            user.isAdmin = ADMIN_EMAILS.includes(user.email);
        }
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// ----------------------------------------------------------------------
// Google Strategy
// ----------------------------------------------------------------------
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'https://webhooks-gwsp.onrender.com/auth/google/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    console.log('✅ Google strategy verify');
    console.log('Profile ID:', profile.id);
    console.log('Email:', profile.emails?.[0]?.value);
    
    try {
      const email = profile.emails?.[0]?.value || null;
      let result = await pool.query('SELECT * FROM users WHERE id = $1', [profile.id]);
      let user = result.rows[0];
      
      if (!user) {
        const insert = await pool.query(
          'INSERT INTO users (id, username, avatar, email, provider) VALUES ($1, $2, $3, $4, $5) RETURNING *',
          [profile.id, profile.displayName, profile.photos[0]?.value, email, 'google']
        );
        user = insert.rows[0];
      } else {
        await pool.query(
          'UPDATE users SET avatar = $1, email = $2 WHERE id = $3',
          [profile.photos[0]?.value, email, profile.id]
        );
        result = await pool.query('SELECT * FROM users WHERE id = $1', [profile.id]);
        user = result.rows[0];
      }
      
      user.isAdmin = ADMIN_EMAILS.includes(user.email);
      return done(null, user);
    } catch (err) {
      console.error('❌ Google strategy error:', err);
      return done(err);
    }
  }
));

// ----------------------------------------------------------------------
// GitHub Strategy
// ----------------------------------------------------------------------
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: 'https://webhooks-gwsp.onrender.com/auth/github/callback',
    scope: ['user:email']
  },
  async (accessToken, refreshToken, profile, done) => {
    console.log('✅ GitHub strategy verify');
    console.log('Profile ID:', profile.id);
    console.log('Username:', profile.username);
    console.log('Emails:', profile.emails);

    try {
      const emailObj = profile.emails && profile.emails.find(e => e.primary === true) || profile.emails?.[0];
      const email = emailObj ? emailObj.value : null;
      const avatar = profile.photos?.[0]?.value || null;
      const username = profile.displayName || profile.username;

      let result = await pool.query('SELECT * FROM users WHERE id = $1', [profile.id]);
      let user = result.rows[0];

      if (!user) {
        const insert = await pool.query(
          'INSERT INTO users (id, username, avatar, email, provider, chosen_username) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
          [profile.id, username, avatar, email, 'github', username]
        );
        user = insert.rows[0];
      } else {
        await pool.query(
          'UPDATE users SET avatar = $1, email = $2 WHERE id = $3',
          [avatar, email, profile.id]
        );
        result = await pool.query('SELECT * FROM users WHERE id = $1', [profile.id]);
        user = result.rows[0];
      }

      user.isAdmin = ADMIN_EMAILS.includes(user.email);
      return done(null, user);
    } catch (err) {
      console.error('❌ GitHub strategy error:', err);
      return done(err);
    }
  }
));

// ----------------------------------------------------------------------
// Discord Manual OAuth (with enhanced error logging)
// ----------------------------------------------------------------------
const DISCORD_CALLBACK_URL = 'https://webhooks-gwsp.onrender.com/auth/discord/callback';
const DISCORD_SCOPES = ['identify', 'email', 'guilds'];

app.get('/auth/discord', (req, res) => {
    const discordAuthUrl = `https://discord.com/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(DISCORD_CALLBACK_URL)}&scope=${encodeURIComponent(DISCORD_SCOPES.join(' '))}`;
    console.log('Redirecting to Discord:', discordAuthUrl);
    res.redirect(discordAuthUrl);
});

app.get('/auth/discord/callback', async (req, res) => {
    console.log('📞 Discord callback reached');
    console.log('Query:', req.query);
    const { code, error } = req.query;
    if (error) {
        console.error('Discord error:', error);
        return res.status(400).send('Discord error: ' + error);
    }
    if (!code) {
        console.error('No code in callback');
        return res.status(400).send('No code provided');
    }
    console.log('✅ Authorization code received (first 10 chars):', code.substring(0, 10) + '...');

    // Exchange code for token
    const params = new URLSearchParams();
    params.append('client_id', process.env.DISCORD_CLIENT_ID);
    params.append('client_secret', process.env.DISCORD_CLIENT_SECRET);
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('redirect_uri', DISCORD_CALLBACK_URL);
    params.append('scope', DISCORD_SCOPES.join(' '));

    try {
        console.log('Exchanging code for token...');
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            body: params,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        // Log response status and headers
        console.log('Token exchange response status:', tokenRes.status);
        console.log('Token exchange response headers:', tokenRes.headers.get('content-type'));

        const responseText = await tokenRes.text(); // Get raw text
        console.log('Token exchange raw response (first 500 chars):', responseText.substring(0, 500));

        if (!tokenRes.ok) {
            console.error('Token exchange failed with status', tokenRes.status);
            return res.status(500).send(`Token exchange failed: ${responseText}`);
        }

        // Try to parse JSON
        let tokenData;
        try {
            tokenData = JSON.parse(responseText);
        } catch (parseErr) {
            console.error('Failed to parse token response as JSON:', parseErr);
            return res.status(500).send('Invalid JSON response from Discord');
        }

        console.log('Token exchange successful, access token received');

        // Fetch user profile
        const userRes = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const profile = await userRes.json();
        console.log('Discord profile:', profile);

        // Extract info
        const id = profile.id;
        const username = profile.username;
        const avatar = profile.avatar ? `https://cdn.discordapp.com/avatars/${id}/${profile.avatar}.png` : null;
        const email = profile.email || null;

        // Save user to database
        let result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        let user = result.rows[0];
        if (!user) {
            console.log('🆕 New Discord user, inserting');
            const insert = await pool.query(
                'INSERT INTO users (id, username, avatar, email, provider) VALUES ($1, $2, $3, $4, $5) RETURNING *',
                [id, username, avatar, email, 'discord']
            );
            user = insert.rows[0];
        } else {
            console.log('🔄 Existing Discord user, updating');
            await pool.query(
                'UPDATE users SET avatar = $1, email = $2 WHERE id = $3',
                [avatar, email, id]
            );
            result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
            user = result.rows[0];
        }

        // Manually log user in via Passport
        req.login(user, (err) => {
            if (err) {
                console.error('Login error:', err);
                return res.status(500).send('Login failed');
            }
            console.log('✅ Discord authentication successful, user:', user.id);
            if (!user.chosen_username) {
                res.redirect('/choose-username');
            } else {
                res.redirect('/');
            }
        });
    } catch (err) {
        console.error('❌ Discord OAuth error:', err);
        res.status(500).send('Discord authentication failed: ' + err.message);
    }
});

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
app.get('/', async (req, res) => {
    console.log('Home route, isAuthenticated:', req.isAuthenticated());
    if (req.isAuthenticated()) {
        req.user.isAdmin = ADMIN_EMAILS.includes(req.user.email);
        try {
            const keysResult = await pool.query(
                'SELECT * FROM webhook_keys WHERE user_id = $1 ORDER BY created_at DESC',
                [req.user.id]
            );
            res.render('index', { user: req.user, keys: keysResult.rows });
        } catch (err) {
            console.error(err);
            res.status(500).send('Database error');
        }
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
            res.redirect('/choose-username');
        } else {
            res.redirect('/');
        }
    }
);

// GitHub login
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

// GitHub callback
app.get('/auth/github/callback', 
    (req, res, next) => {
        console.log('📞 GitHub callback reached');
        if (req.query.error) {
            console.error('GitHub error:', req.query.error);
            return res.status(400).send('GitHub error: ' + req.query.error);
        }
        next();
    },
    passport.authenticate('github', { failureRedirect: '/' }),
    (req, res) => {
        console.log('✅ GitHub authentication successful, user:', req.user.id);
        res.redirect('/');
    }
);

// Username selection
app.get('/choose-username', ensureAuthenticated, (req, res) => {
    res.render('choose-username', { user: req.user });
});

app.post('/choose-username', ensureAuthenticated, async (req, res) => {
    console.log('POST /choose-username body:', req.body);
    const { username } = req.body;
    if (!username || username.length < 3) {
        return res.render('choose-username', { user: req.user, error: 'Username must be at least 3 characters.' });
    }
    try {
        await pool.query('UPDATE users SET chosen_username = $1 WHERE id = $2', [username, req.user.id]);
        req.user.chosen_username = username;
        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) console.error(err);
        res.redirect('/');
    });
});

// Webhook generation (protected)
app.post('/generate', ensureAuthenticated, async (req, res) => {
    const key = crypto.randomBytes(16).toString('hex');
    try {
        await pool.query('INSERT INTO webhook_keys (key, user_id) VALUES ($1, $2)', [key, req.user.id]);
        res.json({ key, webhookUrl: `/webhook/${key}`, viewUrl: `/view/${key}` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

// Public webhook endpoint
app.all('/webhook/:key', async (req, res) => {
    const { key } = req.params;
    try {
        const keyExists = await pool.query('SELECT key FROM webhook_keys WHERE key = $1', [key]);
        if (keyExists.rows.length === 0) {
            return res.status(404).send('Webhook key not found');
        }

        await pool.query(
            'INSERT INTO webhook_requests (key, method, headers, body) VALUES ($1, $2, $3, $4)',
            [key, req.method, JSON.stringify(req.headers), req.body.toString('utf8')]
        );

        res.status(200).send('Webhook received');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// View key data (protected)
app.get('/view/:key', ensureAuthenticated, async (req, res) => {
    const { key } = req.params;
    try {
        const keyOwner = await pool.query('SELECT user_id FROM webhook_keys WHERE key = $1', [key]);
        if (keyOwner.rows.length === 0 || keyOwner.rows[0].user_id !== req.user.id) {
            return res.status(403).send('Forbidden');
        }

        const requests = await pool.query(
            'SELECT method, headers, body, timestamp FROM webhook_requests WHERE key = $1 ORDER BY timestamp DESC',
            [key]
        );
        res.render('view-key', { key, requests: requests.rows, user: req.user });
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

// API endpoint (protected)
app.get('/api/webhook/:key', ensureAuthenticated, async (req, res) => {
    const { key } = req.params;
    try {
        const keyOwner = await pool.query('SELECT user_id FROM webhook_keys WHERE key = $1', [key]);
        if (keyOwner.rows.length === 0 || keyOwner.rows[0].user_id !== req.user.id) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const requests = await pool.query('SELECT * FROM webhook_requests WHERE key = $1 ORDER BY timestamp DESC', [key]);
        res.json(requests.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

// Delete a webhook key (protected, user-owned)
app.post('/delete-key/:key', ensureAuthenticated, async (req, res) => {
    const { key } = req.params;
    try {
        const keyOwner = await pool.query('SELECT user_id FROM webhook_keys WHERE key = $1', [key]);
        if (keyOwner.rows.length === 0 || keyOwner.rows[0].user_id !== req.user.id) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        await pool.query('DELETE FROM webhook_requests WHERE key = $1', [key]);
        await pool.query('DELETE FROM webhook_keys WHERE key = $1', [key]);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

// ----------------------------------------------------------------------
// Admin routes
// ----------------------------------------------------------------------

// Admin dashboard
app.get('/admin', ensureAdmin, async (req, res) => {
    try {
        const totalKeys = await pool.query('SELECT COUNT(*) as count FROM webhook_keys');
        const keys = await pool.query(`
            SELECT wk.key, wk.created_at, u.username, u.email, u.chosen_username
            FROM webhook_keys wk
            JOIN users u ON wk.user_id = u.id
            ORDER BY wk.created_at DESC
        `);
        res.render('admin', { user: req.user, totalKeys: totalKeys.rows[0].count, keys: keys.rows });
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

// Admin view of any webhook key's logs
app.get('/admin/view/:key', ensureAdmin, async (req, res) => {
    const { key } = req.params;
    try {
        const keyExists = await pool.query('SELECT key FROM webhook_keys WHERE key = $1', [key]);
        if (keyExists.rows.length === 0) {
            return res.status(404).send('Webhook key not found');
        }
        const requests = await pool.query(
            'SELECT method, headers, body, timestamp FROM webhook_requests WHERE key = $1 ORDER BY timestamp DESC',
            [key]
        );
        res.render('view-key', { key, requests: requests.rows, user: req.user, isAdminView: true });
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

// Admin delete any webhook key
app.post('/admin/delete-key/:key', ensureAdmin, async (req, res) => {
    const { key } = req.params;
    try {
        const keyExists = await pool.query('SELECT key FROM webhook_keys WHERE key = $1', [key]);
        if (keyExists.rows.length === 0) {
            return res.status(404).json({ error: 'Key not found' });
        }
        await pool.query('DELETE FROM webhook_requests WHERE key = $1', [key]);
        await pool.query('DELETE FROM webhook_keys WHERE key = $1', [key]);
        res.json({ success: true });
    } catch (err) {
        console.error('Error deleting key:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// Webhook tester page
app.get('/admin/tester', ensureAdmin, (req, res) => {
    res.render('tester', { user: req.user });
});

// Proxy endpoint for webhook tester (supports JSON and plain text)
app.post('/admin/proxy', ensureAdmin, express.json(), async (req, res) => {
    const { method, url, body, contentType = 'json' } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'URL required' });
    }
    try {
        const fetchOptions = {
            method: method,
            headers: {}
        };

        // Set Content-Type based on user selection
        if (method === 'POST' || method === 'PATCH') {
            if (contentType === 'json') {
                fetchOptions.headers['Content-Type'] = 'application/json';
                fetchOptions.body = body;
            } else if (contentType === 'text') {
                fetchOptions.headers['Content-Type'] = 'text/plain';
                fetchOptions.body = body;
            }
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

// Debug route
app.get('/debug-me', ensureAuthenticated, (req, res) => {
    res.json({
        id: req.user.id,
        email: req.user.email,
        username: req.user.username,
        chosen_username: req.user.chosen_username,
        provider: req.user.provider,
        isAdmin: req.user.isAdmin,
        adminList: ADMIN_EMAILS
    });
});

// ----------------------------------------------------------------------
// Start server
// ----------------------------------------------------------------------
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
