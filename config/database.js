const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');

// Database setup - PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Helper function to execute queries
const query = async (text, params) => {
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } finally {
    client.release();
  }
};

// Helper function to get a single row
const get = async (text, params) => {
  const result = await query(text, params);
  return result.rows[0] || null;
};

// Helper function to get all rows
const all = async (text, params) => {
  const result = await query(text, params);
  return result.rows;
};

// Helper function for transactions
const transaction = async (callback) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await callback(client);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
};

// Initialize database schema
const initializeDatabase = async () => {
  try {
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS games (
        id TEXT PRIMARY KEY,
        week INTEGER NOT NULL,
        away TEXT NOT NULL,
        home TEXT NOT NULL,
        kickoff TIMESTAMP,
        winner TEXT CHECK(winner IN ('home', 'away')),
        away_score INTEGER,
        home_score INTEGER,
        status TEXT DEFAULT 'scheduled',
        nfl_game_id TEXT,
        UNIQUE(week, away, home)
      );

      CREATE TABLE IF NOT EXISTS picks (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        game_id TEXT NOT NULL,
        pick TEXT NOT NULL CHECK(pick IN ('home', 'away')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, game_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(game_id) REFERENCES games(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS pick_deadlines (
        week INTEGER PRIMARY KEY,
        deadline TIMESTAMP NOT NULL
      );
    `);
    console.log('Database tables initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
    throw error;
  }
};

// Database interface that mimics the SQLite better-sqlite3 API
const db = {
  prepare: (sql) => ({
    get: async (...params) => {
      return await get(sql, params);
    },
    all: async (...params) => {
      return await all(sql, params);
    },
    run: async (...params) => {
      const result = await query(sql, params);
      return { 
        changes: result.rowCount,
        lastInsertRowid: result.rows[0]?.id
      };
    }
  }),
  
  exec: async (sql) => {
    return await query(sql);
  },
  
  transaction: (callback) => {
    return async () => {
      await transaction(async (client) => {
        // Create a temporary db object for the transaction
        const txDb = {
          prepare: (sql) => ({
            run: async (...params) => {
              const result = await client.query(sql, params);
              return { 
                changes: result.rowCount,
                lastInsertRowid: result.rows[0]?.id
              };
            }
          })
        };
        
        // Execute the callback with the transaction db
        await callback(txDb);
      });
    };
  }
};

module.exports = { 
  db, 
  uuidv4, 
  initializeDatabase,
  query,
  get,
  all,
  pool
};