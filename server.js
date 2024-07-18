require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const app = express();
const db = require('./db');  // Import the database connection

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'default_secret_key', // Use a secret key from environment variables or a default one
  resave: false,
  saveUninitialized: true,
}));

// Middleware to check if the user is logged in
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  } else {
    res.redirect('/signin');
  }
}

// Signup route
app.post('/register', async (req, res) => {
  const { username, mobile, email, password } = req.body;

  // Check if email or mobile number already exists
  const checkQuery = 'SELECT * FROM users WHERE email = ? OR mobile = ?';
  db.query(checkQuery, [email, mobile], async (err, results) => {
    if (err) {
      return res.status(500).send('Database error');
    }

    if (results.length > 0) {
      return res.status(400).send('Email or mobile number already exists');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
    const insertQuery = 'INSERT INTO users (username, mobile, email, password) VALUES (?, ?, ?, ?)';
    db.query(insertQuery, [username, mobile, email, hashedPassword], (err, results) => {
      if (err) {
        return res.status(500).send('Error saving user data');
      }

      res.status(201).send('User registered successfully');
    });
  });
});

// Signin route
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) {
      return res.status(500).send('Database error');
    }

    if (results.length === 0) {
      return res.status(400).send('User not found');
    }

    const user = results[0];

    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(400).send('Invalid password');
    }

    req.session.userId = user.id;
    res.redirect('/index');  // Redirect to the index page upon successful login
  });
});

// Serve static HTML files
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/signin', (req, res) => {
  res.sendFile(path.join(__dirname, 'signin.html'));
});

// Serve the index.html file content after successful login
app.get('/index', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve static files (including index.js)
app.use(express.static(__dirname));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

