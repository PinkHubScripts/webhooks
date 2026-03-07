console.log('DISCORD_CLIENT_ID:', process.env.DISCORD_CLIENT_ID);
console.log('DISCORD_CLIENT_SECRET length:', process.env.DISCORD_CLIENT_SECRET ? process.env.DISCORD_CLIENT_SECRET.length : 'MISSING');

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const bodyParser = require('body-parser');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // set to true if using HTTPS (production)
}));

// Passport setup
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  done(null, user);
});

// ---------- Discord Strategy (with absolute URL) ----------
const DISCORD_CALLBACK_URL = 'https://webhooks-gwsp.onrender.com/auth/discord/callback';

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: DISCORD_CALLBACK_URL,  // absolute URL
    scope: ['identify', 'email', 'guilds']
}, (accessToken, refreshToken, profile, done) => {
    try {
        console.log('Discord auth successful for user:', profile.username);
        const stmt = db.prepare(`
            INSERT OR REPLACE INTO users (id, username, avatar)
            VALUES (?, ?, ?)
        `);
        stmt.run(profile.id, profile.username, profile.avatar);
        return done(null, profile);
    } catch (err) {
        console.error('Database error during user save:', err);
        return done(err);
    }
}));

// Add this route BEFORE the passport callback to see what's happening
app.get('/auth/discord/callback', (req, res, next) => {
    console.log('Callback reached. Query:', req.query);
    if (req.query.error) {
        console.error('Discord returned error:', req.query.error);
        return res.status(400).send('Discord error: ' + req.query.error);
    }
    if (!req.query.code) {
        console.error('No code in callback');
        return res.status(400).send('No code provided');
    }
    console.log('Authorization code received:', req.query.code);
    // Now let passport handle it
    next();
}, passport.authenticate('discord', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/');
});

// ---------- Routes ----------

// Home page – shows login button or dashboard
app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    // Fetch user's webhook keys
    const keys = db.prepare('SELECT * FROM webhook_keys WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
    res.render('index', { user: req.user, keys });
  } else {
    res.render('index', { user: null, keys: [] });
  }
});

// Discord auth
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/' }),
  (req, res) => res.redirect('/')
);

// Logout
app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
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
  // Check if key exists
  const keyExists = db.prepare('SELECT key FROM webhook_keys WHERE key = ?').get(key);
  if (!keyExists) {
    return res.status(404).send('Webhook key not found');
  }

  // Store the request
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
  // Verify the key belongs to the user
  const keyOwner = db.prepare('SELECT user_id FROM webhook_keys WHERE key = ?').get(key);
  if (!keyOwner || keyOwner.user_id !== req.user.id) {
    return res.status(403).send('Forbidden');
  }

  // Fetch requests for this key
  const requests = db.prepare(`
    SELECT method, headers, body, timestamp
    FROM webhook_requests
    WHERE key = ?
    ORDER BY timestamp DESC
  `).all(key);

  res.render('view-key', { key, requests });
});

// Optional: JSON API for the key's data (protected)
app.get('/api/webhook/:key', ensureAuthenticated, (req, res) => {
  const { key } = req.params;
  const keyOwner = db.prepare('SELECT user_id FROM webhook_keys WHERE key = ?').get(key);
  if (!keyOwner || keyOwner.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const requests = db.prepare('SELECT * FROM webhook_requests WHERE key = ? ORDER BY timestamp DESC').all(key);
  res.json(requests);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
