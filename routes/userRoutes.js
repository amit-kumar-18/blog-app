const express = require('express');
const db = require('../config/db');
const { isLoggedIn } = require('../middlewares/authMiddleware');

const router = express.Router();

router.get('/', (req, res) => {
  if (req.user) {
    const stmt = db.prepare(
      'SELECT * FROM posts WHERE authorId = ? ORDER BY createdDate DESC'
    );
    const posts = stmt.all(req.user.userid);

    return res.render('dashboard', { posts });
  }
  res.render('index');
});

router.post('/delete-user', isLoggedIn, (req, res) => {
  const stmt = db.prepare('DELETE FROM users WHERE id = ?');
  stmt.run(req.user.userid);

  res.clearCookie('blogApp');
  res.redirect('/');
});

module.exports = router;
