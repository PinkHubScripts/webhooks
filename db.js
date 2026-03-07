const Database = require('better-sqlite3');
const db = new Database('webhooks.db');

// Create tables if they don't exist
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT,
    avatar TEXT,
    provider TEXT DEFAULT 'discord',
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

// Add chosen_username column if missing (safe migration)
try {
  db.exec("ALTER TABLE users ADD COLUMN chosen_username TEXT;");
  console.log("✅ Added chosen_username column to users table.");
} catch (err) {
  // Column already exists – ignore error
  if (!err.message.includes("duplicate column name")) {
    console.error("Error adding column:", err);
  }
}

module.exports = db;
