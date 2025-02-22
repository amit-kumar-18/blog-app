const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../model/db');
const { loginLimiter } = require('../middlewares/rateLimitMiddleware');

const router = express.Router();

router.get('/login', (req, res) => res.render('login'));

router.get('/logout', (req, res) => {
  res.clearCookie('blogApp');
  res.redirect('/');
});

router.post('/login', loginLimiter, (req, res) => {
  const { username = '', password = '' } = req.body;
  let errors = [];

  const userStmt = db.prepare('SELECT * FROM users WHERE username = ?');
  const user = userStmt.get(username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    errors.push('Invalid username / password');
    return res.render('login', { errors });
  }

  const jwtToken = jwt.sign(
    { userid: user.id, username: user.username },
    process.env.JWTKEY,
    { expiresIn: '1d' }
  );

  res.cookie('blogApp', jwtToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 86400000,
  });

  res.redirect('/');
});

router.post('/register', async (req, res) => {
  let { username, password } = req.body;
  const errors = [];

  username = username.trim();
  password = password.trim();

  if (!/^[a-zA-Z0-9]{3,10}$/.test(username)) errors.push('Invalid Username.');
  if (!/^.{8,25}$/.test(password)) errors.push('Invalid Password.');

  if (errors.length) return res.render('index', { errors });

  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    const stmt = db.prepare(
      'INSERT INTO users(username, password) VALUES(?, ?)'
    );
    const result = stmt.run(username, hashedPassword);

    const user = db
      .prepare('SELECT * FROM users WHERE ROWID = ?')
      .get(result.lastInsertRowid);
    const jwtToken = jwt.sign(
      { userid: user.id, username: user.username },
      process.env.JWTKEY,
      { expiresIn: '1d' }
    );

    res.cookie('blogApp', jwtToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 86400000,
    });

    res.redirect('/');
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE')
      return res.render('index', { errors: ['Username already taken.'] });
    res.status(500).send('Internal Server Error');
  }
});

module.exports = router;
