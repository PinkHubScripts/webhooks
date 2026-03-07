const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // required for Render
});

// Initialize tables
const initDb = async () => {
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
};

initDb();

// Helper to run queries with promises (since pg is async)
const query = (text, params) => pool.query(text, params);

// For compatibility with your existing code (prepare/run/get/all),
// we'll create a wrapper that mimics better-sqlite3's sync API,
// but we must adapt your server.js to be async. However, your current code
// uses sync calls. We'll need to refactor server.js to async/await.
// I'll provide an updated server.js that works with async pg.
