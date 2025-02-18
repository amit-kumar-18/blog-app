require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('better-sqlite3')('postApp.db');

db.pragma('journal_mode = WAL');

// database setup
const createTables = db.transaction(() => {
  db.prepare(
    `
            CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username STRING NOT NULL UNIQUE,
            password STRING NOT NULL
            )
        `
  ).run();
});

createTables();

const app = express();
const port = 3000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use((req, res, next) => {
  res.locals.errors = [];
  next();
});

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/register', (req, res) => {
  const { username = '', password = '' } = req.body;
  const errors = [];

  if (typeof username !== 'string') username = '';
  if (typeof password !== 'string') password = '';

  const trimmedUsername = username.trim();
  const trimmedPassword = password.trim();

  if (!trimmedUsername) errors.push('You must provide a Username');
  if (trimmedUsername && trimmedUsername.length < 3)
    errors.push('Username must be at least 3 characters.');
  if (trimmedUsername && trimmedUsername.length > 10)
    errors.push('trimmedUsername cannot exceed 10 characters.');
  if (trimmedUsername && !trimmedUsername.match(/^[a-zA-Z0-9]+$/))
    errors.push('Username can only contain letters and numbers.');

  if (!trimmedPassword) errors.push('You must provide a Password');
  if (trimmedPassword && trimmedPassword.length < 8)
    errors.push('Password must be at least 8 characters.');
  if (trimmedPassword && trimmedPassword.length > 25)
    errors.push('Password cannot exceed 25 characters.');

  if (errors.length) {
    return res.render('index', { errors });
  }

  // save the new user into a database
  try {
    const salt = bcrypt.genSaltSync();
    const encryptPassword = bcrypt.hashSync(trimmedPassword, salt);
    const stmt = db.prepare(
      'INSERT INTO users(username, password) VALUES(?, ?)'
    );
    const result = stmt.run(trimmedUsername, encryptPassword);

    const lookupStmt = db.prepare('SELECT * FROM users WHERE ROWID = ?');
    const user = lookupStmt.get(result.lastInsertRowid);

    // log the user in by giving them a cookie
    const jwtToken = jwt.sign(
      {
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
        userid: user.id,
        username: user.username,
      },
      process.env.JWTKEY
    );

    res.cookie('postApp', jwtToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60 * 24,
    });
    res.send('Thank you');
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.render('index', { errors: ['Username already taken.'] });
    }
    console.log(err, err.code);
    return res.status(500).send('Internal Server Error');
  }
});

app.listen(port, () => {
  console.log(`App listening on port http://localhost:${port}`);
});
