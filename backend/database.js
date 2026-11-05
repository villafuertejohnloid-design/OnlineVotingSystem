const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'voting.db');

const PROGRAMS = [
  'CICS - BSIT', 'CICS - BLIS', 'CAS - BS Psych', 'CAS - BSSW',
  'CAS - AB Econ', 'CAS - AB Sociology', 'CBM - BSBA', 'CBM - BSTM',
  'CTE - BEEd', 'CTE - BSEd', 'CCJE - BS Crim'
];

const DEFAULT_POSITIONS = [
  'President', 'Vice President', 'Secretary', 'Treasurer', 'Auditor',
  'Public Information Officer'
];

async function initializeDatabase() {
  const SQL = await initSqlJs();
  const db = fs.existsSync(DB_PATH)
    ? new SQL.Database(fs.readFileSync(DB_PATH))
    : new SQL.Database();

  db.run('PRAGMA foreign_keys = ON');

  function hasColumn(table, column) {
    const result = db.exec(`PRAGMA table_info("${table}")`);
    return result.length > 0 && result[0].values.some(row => row[1] === column);
  }

  function addColumnIfMissing(table, column, definition) {
    if (!hasColumn(table, column)) {
      db.run(`ALTER TABLE "${table}" ADD COLUMN "${column}" ${definition}`);
      console.log(`Database migration: added ${table}.${column}`);
    }
  }

  function queryOne(sql, params = []) {
    const statement = db.prepare(sql);
    try {
      statement.bind(params);
      return statement.step() ? statement.getAsObject() : null;
    } finally {
      statement.free();
    }
  }

  db.run(`CREATE TABLE IF NOT EXISTS voters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL DEFAULT '',
    username TEXT UNIQUE,
    password_hash TEXT NOT NULL DEFAULT '',
    school_id_number TEXT UNIQUE,
    program TEXT DEFAULT '',
    has_voted INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  addColumnIfMissing('voters', 'full_name', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing('voters', 'username', 'TEXT');
  addColumnIfMissing('voters', 'password_hash', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing('voters', 'school_id_number', 'TEXT');
  addColumnIfMissing('voters', 'program', "TEXT DEFAULT ''");
  addColumnIfMissing('voters', 'has_voted', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing('voters', 'created_at', 'TEXT');

  // Migrate values from older schemas when those columns exist.
  if (hasColumn('voters', 'school_id_number')) {
    db.run("UPDATE voters SET username = school_id_number WHERE (username IS NULL OR username = '') AND school_id_number IS NOT NULL");
    db.run("UPDATE voters SET school_id_number = username WHERE (school_id_number IS NULL OR school_id_number = '') AND username IS NOT NULL");
  }
  if (hasColumn('voters', 'password')) {
    db.run("UPDATE voters SET password_hash = password WHERE (password_hash IS NULL OR password_hash = '') AND password IS NOT NULL");
  }

  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL DEFAULT ''
  )`);
  addColumnIfMissing('admins', 'username', 'TEXT');
  addColumnIfMissing('admins', 'password_hash', "TEXT NOT NULL DEFAULT ''");
  if (hasColumn('admins', 'password')) {
    db.run("UPDATE admins SET password_hash = password WHERE (password_hash IS NULL OR password_hash = '') AND password IS NOT NULL");
  }

  db.run(`CREATE TABLE IF NOT EXISTS positions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL UNIQUE,
    sort_order INTEGER NOT NULL DEFAULT 0
  )`);
  addColumnIfMissing('positions', 'title', "TEXT NOT NULL DEFAULT 'Untitled Position'");
  addColumnIfMissing('positions', 'sort_order', 'INTEGER NOT NULL DEFAULT 0');

  db.run(`CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL DEFAULT '',
    position_id INTEGER,
    platform TEXT DEFAULT '',
    FOREIGN KEY (position_id) REFERENCES positions(id)
  )`);
  addColumnIfMissing('candidates', 'full_name', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing('candidates', 'position_id', 'INTEGER');
  addColumnIfMissing('candidates', 'platform', "TEXT DEFAULT ''");

  db.run(`CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_id INTEGER NOT NULL,
    candidate_id INTEGER NOT NULL,
    position_id INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (voter_id, position_id),
    FOREIGN KEY (voter_id) REFERENCES voters(id),
    FOREIGN KEY (candidate_id) REFERENCES candidates(id),
    FOREIGN KEY (position_id) REFERENCES positions(id)
  )`);
  addColumnIfMissing('votes', 'voter_id', 'INTEGER');
  addColumnIfMissing('votes', 'candidate_id', 'INTEGER');
  addColumnIfMissing('votes', 'position_id', 'INTEGER');
  addColumnIfMissing('votes', 'created_at', 'TEXT');

  // Keep both modern and older activity-log column names compatible.
  db.run(`CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL DEFAULT 'System',
    username TEXT NOT NULL DEFAULT 'System',
    action TEXT NOT NULL DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  addColumnIfMissing('activity_logs', 'actor', "TEXT NOT NULL DEFAULT 'System'");
  addColumnIfMissing('activity_logs', 'username', "TEXT NOT NULL DEFAULT 'System'");
  addColumnIfMissing('activity_logs', 'action', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing('activity_logs', 'created_at', 'TEXT');

  db.run(`CREATE TABLE IF NOT EXISTS modules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  // Existing account records are preserved. Create the demo admin only if none exists.
  const adminCount = queryOne('SELECT COUNT(*) AS n FROM admins').n;
  if (Number(adminCount) === 0) {
    const passwordHash = await bcrypt.hash('Admin123!', 10);
    db.run('INSERT INTO admins (username, password_hash) VALUES (?, ?)', ['admin', passwordHash]);
    console.log('Default admin created: username admin, password Admin123!');
  }

  let maxOrder = Number(queryOne('SELECT COALESCE(MAX(sort_order), 0) AS n FROM positions').n) || 0;
  for (const title of DEFAULT_POSITIONS) {
    const found = queryOne('SELECT id FROM positions WHERE lower(title) = lower(?)', [title]);
    if (!found) {
      maxOrder += 1;
      db.run('INSERT INTO positions (title, sort_order) VALUES (?, ?)', [title, maxOrder]);
    }
  }

  function saveDatabase() {
    fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
  }

  saveDatabase();
  console.log('Database initialized and schema checked.');
  return { db, saveDatabase, PROGRAMS };
}

module.exports = initializeDatabase;
