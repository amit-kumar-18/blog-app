require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const marked = require('marked');
const cookieParser = require('cookie-parser');
const sanitizeHTML = require('sanitize-html');
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

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      createdDate TEXT DEFAULT (strftime('%H:%M:%S - %d/%m/%Y', 'now', 'localtime')),
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      authorId INTEGER,
      FOREIGN KEY (authorId) REFERENCES users(id) ON DELETE CASCADE
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
app.use(cookieParser());

// Middlewares
app.use((req, res, next) => {
  // make our markdown function available
  res.locals.filterUserHTML = (content) => {
    return sanitizeHTML(marked.parse(content), {
      allowedTags: [
        'p',
        'br',
        'ul',
        'li',
        'ol',
        'strong',
        'i',
        'h1',
        'h2',
        'h3',
        'h4',
        'h5',
        'h6',
      ],
      allowedAttributes: {},
    });
  };

  res.locals.errors = [];

  // try to decode the incoming cookie.
  try {
    const decode = jwt.verify(req.cookies.postApp, process.env.JWTKEY);
    req.user = decode;
  } catch (err) {
    req.user = false;
  }

  res.locals.user = req.user;
  console.log(req.user);

  next();
});

const isLoggedIn = (req, res, next) => {
  if (req.user) {
    return next();
  }
  return res.redirect('/');
};

app.get('/', (req, res) => {
  if (req.user) {
    const stmt = db.prepare(
      'SELECT * FROM posts WHERE authorId = ? ORDER BY createdDate DESC'
    );
    const posts = stmt.all(req.user.userid);

    return res.render('dashboard', { posts });
  }
  res.render('index');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/logout', (req, res) => {
  res.clearCookie('postApp');
  res.redirect('/');
});

app.get('/create-post', isLoggedIn, (req, res) => {
  res.render('create-post');
});

app.get('/post/:id', (req, res) => {
  const stmt = db.prepare(
    'SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorId = users.id WHERE posts.id = ?'
  );
  const post = stmt.get(req.params.id);

  if (!post) {
    return res.redirect('/');
  }

  const isAuthor = post.authorId === req.user.userid;

  res.render('post', { post, isAuthor });
});

app.get('/edit-post/:id', isLoggedIn, (req, res) => {
  // try to look up the post in question.
  const stmt = db.prepare('SELECT * FROM posts WHERE id = ?');
  const post = stmt.get(req.params.id);

  // if you're not the author, redirect to homepage.
  if (post.authorId !== req.user.userid || !post) {
    return res.redirect('/');
  }

  // otherwise, render the edit post template.
  res.render('edit-post', { post });
});

app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  let errors = [];

  if (typeof username !== 'string') username = '';
  if (typeof password !== 'string') password = '';

  if (username.trim() == '' || username == '')
    errors = ['Invalid username / password'];

  if (errors.length) {
    return res.render('login', { errors });
  }

  const userStmt = db.prepare('SELECT * FROM users WHERE username = ?');
  const user = userStmt.get(username);

  if (!user) {
    errors = ['Invalid username / password'];
    return res.render('login', { errors });
  }

  const isValid = bcrypt.compareSync(password, user.password);

  if (!isValid) {
    errors = ['Invalid username / password'];
    return res.render('login', { errors });
  }

  // Give a cookie and redirect.
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
  res.redirect('/');
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
    res.redirect('/');
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.render('index', { errors: ['Username already taken.'] });
    }
    console.error(err, err.code);
    return res.status(500).send('Internal Server Error');
  }
});

const postValidation = (req) => {
  const errors = [];
  let { title, body } = req.body;

  if (typeof title !== 'string') title = '';
  if (typeof body !== 'string') body = '';

  // Trim and sanitize input
  title = sanitizeHTML(title.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });
  body = sanitizeHTML(body.trim(), { allowedTags: [], allowedAttributes: {} });

  if (!title) errors.push('Title is required.');
  if (!body) errors.push('Body content is required.');

  return errors;
};

app.post('/create-post', isLoggedIn, (req, res) => {
  const { title, body } = req.body;
  const errors = postValidation(req);

  if (errors.length) {
    return res.render('create-post', { errors });
  }

  // save into database.
  const stmt = db.prepare(
    'INSERT INTO posts (title, body, authorId) VALUES (?, ?, ?)'
  );
  const result = stmt.run(title, body, req.user.userid);

  const getPostStatement = db.prepare('SELECT * FROM posts WHERE ROWID = ?');
  const realPost = getPostStatement.get(result.lastInsertRowid);

  res.redirect(`/post/${realPost.id}`);
});

app.post('/edit-post/:id', isLoggedIn, (req, res) => {
  const stmt = db.prepare('SELECT * FROM posts WHERE id = ?');
  const post = stmt.get(req.params.id);

  // if you're not the author, redirect to homepage.
  if (post.authorId !== req.user.userid || !post) {
    return res.redirect('/');
  }

  const errors = postValidation(req);
  if (errors.length) {
    return res.render('edit-post', { errors });
  }
  const updateStmt = db.prepare(
    'UPDATE posts SET title = ?, body = ? WHERE id = ?'
  );
  updateStmt.run(req.body.title, req.body.body, req.params.id);

  res.redirect(`/post/${req.params.id}`);
});

app.post('/delete-post/:id', isLoggedIn, (req, res) => {
  // try to loop up the post in question.
  const stmt = db.prepare('SELECT * FROM posts WHERE id = ?');
  const post = stmt.get(req.params.id);

  // if you're not the author or invalid post, redirect to homepage.
  if (!post || post.authorId !== req.user.userid) {
    return res.redirect('/');
  }

  const deleteStmt = db.prepare('DELETE from posts WHERE id = ?');
  deleteStmt.run(req.params.id);

  res.redirect('/');
});

app.post('/delete-user', isLoggedIn, (req, res) => {
  const stmt = db.prepare('DELETE FROM users WHERE id = ?');
  stmt.run(req.user.userid);

  res.clearCookie('postApp');
  res.redirect('/');
});

app.listen(port, () => {
  console.log(`App listening on port http://localhost:${port}`);
});
