const Database = require('better-sqlite3');
const db = new Database('blogApp.db');

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');

const createTables = () => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      createdDate TEXT DEFAULT (strftime('%H:%M:%S - %d/%m/%Y', 'now', 'localtime')),
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      authorId INTEGER,
      FOREIGN KEY (authorId) REFERENCES users(id) ON DELETE CASCADE
    );
  `);
};

createTables();

module.exports = db;
