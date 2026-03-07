const Database = require('better-sqlite3');
const db = new Database('webhooks.db');

// Create tables if not exist
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT,
    avatar TEXT,
    email TEXT,
    chosen_username TEXT,
    provider TEXT DEFAULT 'google',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS webhook_keys (
    key TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS webhook_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    method TEXT,
    headers TEXT,
    body TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (key) REFERENCES webhook_keys(key)
  );
`);

// Add email column if missing (safe migration)
try {
  db.exec("ALTER TABLE users ADD COLUMN email TEXT;");
  console.log("✅ Added email column to users table.");
} catch (err) {
  if (!err.message.includes("duplicate column name")) {
    console.error("Error adding column:", err);
  }
}

module.exports = db;
