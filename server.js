require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('./db');

const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin12345';
const DAY = 24 * 60 * 60 * 1000;
const ALLOWED_DAYS = [7, 30, 90, 180, 365, 9999];

const app = express();
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const now = () => Date.now();
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function schema(dialect) {
  const auto = dialect === 'sqlite' ? 'INTEGER PRIMARY KEY AUTOINCREMENT' : 'INT PRIMARY KEY AUTO_INCREMENT';
  const big = dialect === 'sqlite' ? 'INTEGER' : 'BIGINT';
  const vc = n => (dialect === 'sqlite' ? 'TEXT' : `VARCHAR(${n})`);
  const suf = dialect === 'sqlite' ? '' : ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4';

  return [
    `CREATE TABLE IF NOT EXISTS users (
      uid ${auto}, username ${vc(64)} NOT NULL UNIQUE, username_lower ${vc(64)} NOT NULL UNIQUE,
      password_hash ${vc(255)} NOT NULL, role ${vc(16)} NOT NULL DEFAULT 'player',
      sub_expires_at ${big} NOT NULL DEFAULT 0, hwid_resets INT NOT NULL DEFAULT 0, created_at ${big} NOT NULL
    )${suf}`,
    `CREATE TABLE IF NOT EXISTS sessions (
      token ${vc(128)} PRIMARY KEY, uid INT NOT NULL, expires_at ${big} NOT NULL
    )${suf}`,
    `CREATE TABLE IF NOT EXISTS sub_keys (
      id ${auto}, key_code ${vc(64)} NOT NULL UNIQUE, days INT NOT NULL, created_by INT,
      created_at ${big} NOT NULL, used_by INT NULL, used_at ${big} NULL
    )${suf}`
  ];
}

async function initDb() {
  for (const sql of schema(db.dialect)) await db.exec(sql);
  const exists = await db.get('SELECT uid FROM users WHERE username_lower = ?', [ADMIN_USERNAME.toLowerCase()]);
  if (!exists) {
    await db.run(
      'INSERT INTO users (username, username_lower, password_hash, role, sub_expires_at, hwid_resets, created_at) VALUES (?,?,?,?,?,?,?)',
      [ADMIN_USERNAME, ADMIN_USERNAME.toLowerCase(), bcrypt.hashSync(ADMIN_PASSWORD, 10), 'owner', 0, 0, now()]
    );
    console.log(`[seed] Создан владелец: ${ADMIN_USERNAME}`);
  }
}

function publicUser(u) {
  const exp = Number(u.sub_expires_at) || 0;
  return { uid: u.uid, username: u.username, role: u.role, subExpiresAt: exp, subActive: exp > now(), hwidResets: Number(u.hwid_resets) || 0 };
}

async function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Нет токена' });
    const s = await db.get('SELECT * FROM sessions WHERE token = ?', [token]);
    if (!s || Number(s.expires_at) < now()) {
      if (s) await db.run('DELETE FROM sessions WHERE token = ?', [token]);
      return res.status(401).json({ error: 'Сессия истекла' });
    }
    const u = await db.get('SELECT * FROM users WHERE uid = ?', [s.uid]);
    if (!u) return res.status(401).json({ error: 'Пользователь не найден' });
    req.user = u; req.token = token; next();
  } catch (e) { next(e); }
}

const adminOnly = (req, res, next) =>
  (req.user.role !== 'owner' && req.user.role !== 'admin') ? res.status(403).json({ error: 'Доступ только для персонала' }) : next();

async function createSession(uid) {
  const token = crypto.randomBytes(32).toString('hex');
  await db.run('INSERT INTO sessions (token, uid, expires_at) VALUES (?,?,?)', [token, uid, now() + 30 * DAY]);
  return token;
}

function newKeyCode() {
  const hex = crypto.randomBytes(6).toString('hex').toUpperCase();
  return 'GARM-' + hex.match(/.{1,4}/g).join('-');
}

app.post('/api/register', wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Некорректные данные' });
  const uname = username.trim();
  if (!/^[a-zA-Z0-9_]{3,24}$/.test(uname)) return res.status(400).json({ error: 'Логин: 3-24 символа' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  const lower = uname.toLowerCase();
  if (await db.get('SELECT uid FROM users WHERE username_lower = ?', [lower])) return res.status(409).json({ error: 'Логин занят' });

  const r = await db.run(
    'INSERT INTO users (username, username_lower, password_hash, role, sub_expires_at, hwid_resets, created_at) VALUES (?,?,?,?,?,?,?)',
    [uname, lower, bcrypt.hashSync(password, 10), 'player', 0, 0, now()]
  );
  const user = await db.get('SELECT * FROM users WHERE uid = ?', [r.lastInsertRowid]);
  res.json({ token: await createSession(user.uid), user: publicUser(user) });
}));

app.post('/api/login', wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Некорректные данные' });
  const user = await db.get('SELECT * FROM users WHERE username_lower = ?', [username.trim().toLowerCase()]);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Неверный логин или пароль' });
  res.json({ token: await createSession(user.uid), user: publicUser(user) });
}));

app.post('/api/logout', auth, wrap(async (req, res) => {
  await db.run('DELETE FROM sessions WHERE token = ?', [req.token]); res.json({ ok: true });
}));

app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post('/api/redeem', auth, wrap(async (req, res) => {
  const key = String(req.body?.key || '').trim().toUpperCase();
  if (!key) return res.status(400).json({ error: 'Введите ключ' });
  const row = await db.get('SELECT * FROM sub_keys WHERE key_code = ? AND used_by IS NULL', [key]);
  if (!row) return res.status(404).json({ error: 'Ключ не найден или использован' });
  const lock = await db.run('UPDATE sub_keys SET used_by = ?, used_at = ? WHERE id = ? AND used_by IS NULL', [req.user.uid, now(), row.id]);
  if (lock.changes !== 1) return res.status(409).json({ error: 'Ключ уже использован' });

  const newExp = Math.max(now(), Number(req.user.sub_expires_at) || 0) + Number(row.days) * DAY;
  await db.run('UPDATE users SET sub_expires_at = ? WHERE uid = ?', [newExp, req.user.uid]);
  await db.run('DELETE FROM sub_keys WHERE id = ?', [row.id]);
  res.json({ user: publicUser(await db.get('SELECT * FROM users WHERE uid = ?', [req.user.uid])), addedDays: Number(row.days) });
}));

app.get('/api/admin/users', auth, adminOnly, wrap(async (req, res) => {
  res.json((await db.all('SELECT * FROM users ORDER BY uid ASC')).map(publicUser));
}));

app.post('/api/admin/users/:uid/sub', auth, adminOnly, wrap(async (req, res) => {
  const uid = parseInt(req.params.uid, 10), days = parseInt(req.body?.days, 10);
  if (!Number.isFinite(days) || days < 0) return res.status(400).json({ error: 'Некорректные дни' });
  const user = await db.get('SELECT * FROM users WHERE uid = ?', [uid]);
  if (!user) return res.status(404).json({ error: 'Не найден' });
  const newExp = days === 0 ? 0 : Math.max(now(), Number(user.sub_expires_at) || 0) + days * DAY;
  await db.run('UPDATE users SET sub_expires_at = ? WHERE uid = ?', [newExp, uid]);
  res.json({ user: publicUser(await db.get('SELECT * FROM users WHERE uid = ?', [uid])) });
}));

app.post('/api/admin/users/:uid/role', auth, adminOnly, wrap(async (req, res) => {
  const uid = parseInt(req.params.uid, 10), role = req.body?.role;
  if (!['player', 'user', 'media', 'owner', 'admin'].includes(role)) return res.status(400).json({ error: 'Некорректная роль' });
  if (uid === req.user.uid && role !== 'owner') return res.status(400).json({ error: 'Нельзя понизить себя' });
  await db.run('UPDATE users SET role = ? WHERE uid = ?', [role, uid]);
  res.json({ ok: true });
}));

app.delete('/api/admin/users/:uid', auth, adminOnly, wrap(async (req, res) => {
  const uid = parseInt(req.params.uid, 10);
  const u = await db.get('SELECT * FROM users WHERE uid = ?', [uid]);
  if (!u) return res.status(404).json({ error: 'Не найден' });
  if (u.role === 'owner') return res.status(400).json({ error: 'Нельзя удалить владельца' });
  await db.run('DELETE FROM sessions WHERE uid = ?', [uid]);
  await db.run('DELETE FROM users WHERE uid = ?', [uid]);
  res.json({ ok: true });
}));

app.get('/api/admin/keys', auth, adminOnly, wrap(async (req, res) => {
  res.json((await db.all('SELECT * FROM sub_keys ORDER BY id DESC')).map(r => ({ id: r.id, key: r.key_code, days: r.days })));
}));

app.post('/api/admin/keys', auth, adminOnly, wrap(async (req, res) => {
  const days = parseInt(req.body?.days, 10), count = Math.min(Math.max(parseInt(req.body?.count, 10) || 1, 1), 50);
  if (!ALLOWED_DAYS.includes(days)) return res.status(400).json({ error: 'Недопустимый срок' });
  const created = [];
  for (let i = 0; i < count; i++) {
    let code, taken = true;
    while (taken) { code = newKeyCode(); taken = !!(await db.get('SELECT id FROM sub_keys WHERE key_code = ?', [code])); }
    await db.run('INSERT INTO sub_keys (key_code, days, created_by, created_at) VALUES (?,?,?,?)', [code, days, req.user.uid, now()]);
    created.push(code);
  }
  res.json({ keys: created });
}));

app.delete('/api/admin/keys/:id', auth, adminOnly, wrap(async (req, res) => {
  await db.run('DELETE FROM sub_keys WHERE id = ?', [parseInt(req.params.id, 10)]);
  res.json({ ok: true });
}));

app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Ошибка сервера' }); });

initDb().then(() => app.listen(PORT, () => console.log(`✅ Сайт запущен`)))
  .catch(e => { console.error('Ошибка БД:', e); process.exit(1); });
