const SQLite = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');

// Database setup
const db = new SQLite('nfl_picks.db');
db.pragma('journal_mode = WAL');

// Initialize database schema
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin BOOLEAN DEFAULT FALSE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS games (
  id TEXT PRIMARY KEY,
  week INTEGER NOT NULL,
  away TEXT NOT NULL,
  home TEXT NOT NULL,
  kickoff TEXT, -- ISO datetime
  winner TEXT,  -- 'away' | 'home' | NULL until decided
  away_score INTEGER,
  home_score INTEGER,
  status TEXT DEFAULT 'scheduled', -- 'scheduled', 'in_progress', 'final'
  nfl_game_id TEXT, -- External NFL API game ID
  UNIQUE(week, away, home)
);

CREATE TABLE IF NOT EXISTS pick_deadlines (
  week INTEGER PRIMARY KEY,
  deadline TEXT NOT NULL, -- ISO datetime when picks close
  is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS picks (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  game_id TEXT NOT NULL,
  pick TEXT NOT NULL, -- 'away' | 'home'
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(user_id, game_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(game_id) REFERENCES games(id) ON DELETE CASCADE
);
`);

module.exports = { db, uuidv4 };
