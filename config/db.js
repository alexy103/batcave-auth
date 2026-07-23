const path = require('path');
const Database = require('better-sqlite3');

const db = new Database(path.resolve(__dirname, 'database.db'));

// Création de la table avec `username` UNIQUE
db.prepare(
	`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'user',
    passwords_retry INTEGER,
    two_factor_secret TEXT NULL,
    two_factor_enabled INTEGER DEFAULT 0
  )
`,
).run();

db.prepare(
	`
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    content TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`,
).run();

db.prepare(
	`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    timestamp TIMESTAMP
  )
`,
).run();

db.prepare(
	`
  CREATE TABLE IF NOT EXISTS connexions_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT CHECK(action IN ('LOGIN', 'LOGOUT', 'FRAUD')),
    ip_address TEXT,
    user_agent TEXT,
    timestamp TIMESTAMP
  )
`,
).run();

db.prepare(
	`
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`,
).run();

db.prepare(
	`
  CREATE TABLE IF NOT EXISTS oauth_sessions (
    state TEXT PRIMARY KEY,
    code_verifier TEXT NOT NULL,
    nonce TEXT,
    provider TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`,
).run();

db.prepare(
	`
  CREATE TABLE IF NOT EXISTS oauth_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sub TEXT NOT NULL,
    username TEXT,
    role TEXT DEFAULT 'user',
    provider TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider, sub)
  )
`,
).run();

module.exports = db;
