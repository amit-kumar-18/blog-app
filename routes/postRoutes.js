const express = require('express');
const db = require('../model/db');
const sanitizeHTML = require('sanitize-html');
const {
  isLoggedIn,
  authenticateUser,
} = require('../middlewares/authMiddleware');

const router = express.Router();

const postValidation = (req, res, next) => {
  let { title, body } = req.body;
  req.errors = [];

  title = sanitizeHTML(title.trim(), { allowedTags: [] });
  body = sanitizeHTML(body.trim(), { allowedTags: [] });

  if (!title) req.errors.push('Title is required.');
  if (!body) req.errors.push('Body content is required.');

  next();
};

router.get('/create-post', isLoggedIn, (req, res) => res.render('create-post'));

router.get('/post/:id', (req, res) => {
  const stmt = db.prepare(
    'SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorId = users.id WHERE posts.id = ?'
  );
  const post = stmt.get(req.params.id);

  if (!post) return res.redirect('/');

  const isAuthor = req.user ? post.authorId === req.user.userid : false;
  res.render('post', { post, isAuthor });
});

router.post('/create-post', isLoggedIn, postValidation, (req, res) => {
  if (req.errors.length)
    return res.render('create-post', { errors: req.errors });

  const stmt = db.prepare(
    'INSERT INTO posts (title, body, authorId) VALUES (?, ?, ?)'
  );
  const result = stmt.run(req.body.title, req.body.body, req.user.userid);
  const post = db
    .prepare('SELECT * FROM posts WHERE ROWID = ?')
    .get(result.lastInsertRowid);

  res.redirect(`/post/${post.id}`);
});

router.get('/edit-post/:id', isLoggedIn, (req, res) => {
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

router.post('/edit-post/:id', isLoggedIn, postValidation, (req, res) => {
  const stmt = db.prepare('SELECT * FROM posts WHERE id = ?');
  const post = stmt.get(req.params.id);

  if (!post || post.authorId !== req.user.userid) {
    return res.status(403).redirect('/');
  }

  if (req.errors.length) return res.render('edit-post', { errors: req.errors });

  db.prepare('UPDATE posts SET title = ?, body = ? WHERE id = ?').run(
    req.body.title,
    req.body.body,
    req.params.id
  );

  res.redirect(`/post/${req.params.id}`);
});

router.post('/delete-post/:id', isLoggedIn, (req, res) => {
  const stmt = db.prepare('SELECT * FROM posts WHERE id = ?');
  const post = stmt.get(req.params.id);

  if (!post || post.authorId !== req.user.userid) {
    return res.status(403).redirect('/');
  }

  db.prepare('DELETE FROM posts WHERE id = ?').run(req.params.id);
  res.redirect('/');
});

// other user's posts
router.get('/posts', authenticateUser, (req, res) => {
  const stmt = db.prepare(
    'SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorId = users.id WHERE posts.authorId != ? ORDER BY createdDate DESC                                    '
  );
  const posts = stmt.all(req.user.userid);
  res.render('all-posts', { posts });
});

module.exports = router;
