const path = require('path');
const dialect = (process.env.DB_DIALECT || 'sqlite').toLowerCase();

let impl;

if (dialect === 'mysql' || dialect === 'mariadb') {
  const mysql = require('mysql2/promise');
  const opts = process.env.DATABASE_URL
    ? process.env.DATABASE_URL
    : {
        host: process.env.DB_HOST,
        port: Number(process.env.DB_PORT) || 3306,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        waitForConnections: true,
        connectionLimit: 10
      };
  const pool = mysql.createPool(opts);
  impl = {
    dialect: 'mysql',
    async all(sql, params = []) { const [r] = await pool.query(sql, params); return r; },
    async get(sql, params = []) { const [r] = await pool.query(sql, params); return r[0]; },
    async run(sql, params = []) { const [r] = await pool.query(sql, params); return { lastInsertRowid: r.insertId, changes: r.affectedRows }; },
    async exec(sql) { await pool.query(sql); }
  };
} else {
  const Database = require('better-sqlite3');
  const db = new Database(process.env.DB_PATH || path.join(__dirname, 'garmonia.db'));
  db.pragma('journal_mode = WAL');
  impl = {
    dialect: 'sqlite',
    async all(sql, params = []) { return db.prepare(sql).all(...params); },
    async get(sql, params = []) { return db.prepare(sql).get(...params); },
    async run(sql, params = []) { const r = db.prepare(sql).run(...params); return { lastInsertRowid: Number(r.lastInsertRowid), changes: r.changes }; },
    async exec(sql) { db.exec(sql); }
  };
}

module.exports = impl;