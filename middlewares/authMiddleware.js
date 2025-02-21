const jwt = require('jsonwebtoken');
const marked = require('marked');
const sanitizeHTML = require('sanitize-html');

const ALLOWED_TAGS = [
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
];

const isLoggedIn = (req, res, next) => {
  if (req.user) return next();
  res.status(401).redirect('/');
};

const authenticateUser = (req, res, next) => {
  res.locals.filterUserHTML = (content) =>
    sanitizeHTML(marked.parse(content), {
      allowedTags: ALLOWED_TAGS,
      allowedAttributes: {},
    });

  res.locals.errors = [];
  try {
    const token = req.cookies.blogApp;
    if (token) {
      req.user = jwt.verify(token, process.env.JWTKEY);
      res.locals.user = req.user;
    } else {
      req.user = null;
    }
  } catch (err) {
    req.user = null;
  }
  res.locals.user = req.user;
  next();
};

module.exports = { isLoggedIn, authenticateUser };
