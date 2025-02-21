require('dotenv').config();

// imports
const express = require('express');
const cookieParser = require('cookie-parser');
const { authenticateUser } = require('./middlewares/authMiddleware');
const authRoutes = require('./routes/authRoutes');
const postRoutes = require('./routes/postRoutes');
const userRoute = require('./routes/userRoutes');

const app = express();
const port = 3000;

app.set('view engine', 'ejs');
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static('public'));
app.use(authenticateUser);
app.use(authRoutes);
app.use(postRoutes);
app.use(userRoute);

app.listen(port, () =>
  console.log(`App listening on http://localhost:${port}`)
);
