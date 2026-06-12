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
    passwords_retry INTEGER
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
    username INTEGER,
    timestamp TIMESTAMP
  )
`,
).run();
module.exports = db;
