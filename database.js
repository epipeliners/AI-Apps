const { Pool } = require('pg');

// Create a connection pool using individual parameters
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: { rejectUnauthorized: false }
});

async function initDb() {
  const client = await pool.connect();
  try {
    // Create users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        twofa_secret TEXT,
        twofa_enabled INTEGER DEFAULT 0,
        role TEXT DEFAULT 'user'
      )
    `);

    // Create session table for connect-pg-simple
    // Define primary key directly in CREATE TABLE to avoid duplicate PK errors
    await client.query(`
      CREATE TABLE IF NOT EXISTS "session" (
        "sid" varchar NOT NULL COLLATE "default",
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL,
        PRIMARY KEY ("sid")
      )
    `);

    // Create index on expire column (if not exists)
    await client.query(`
      CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire")
    `);

    // Create default admin if none exists
    const adminCheck = await client.query("SELECT COUNT(*) FROM users WHERE role = 'admin'");
    if (parseInt(adminCheck.rows[0].count) === 0) {
      const bcrypt = require('bcrypt');
      const hash = await bcrypt.hash('admin123', 10);
      await client.query(
        "INSERT INTO users (email, password, role) VALUES ($1, $2, $3)",
        ['admin@ai-apps.local', hash, 'admin']
      );
      console.log('✅ Default admin created: admin@ai-apps.local / admin123');
    }
    console.log('✅ Database initialized');
  } catch (err) {
    console.error('❌ DB init error:', err);
  } finally {
    client.release();
  }
}

initDb();

module.exports = pool;