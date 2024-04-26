const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const port = 8080;

// MySQL Connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Charchit@1995',
    database: 'tablelist_user',
});

// Connect to MySQL
connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL: ' + err.stack);
        return;
    }
    console.log('Connected to MySQL as id ' + connection.threadId);
});

// Middleware for parsing JSON bodies
app.use(express.json());

// Session middleware configuration
app.use(session({
    secret: 'your_secret_key', // Change this to a long, random string
    resave: false,
    saveUninitialized: true
}));


// GET all users endpoint
app.get('/users', (req, res) => {
  connection.query('SELECT * FROM users', (error, results, fields) => {
      if (error) {
          console.error('Error fetching users: ' + error);
          return res.status(500).json({ error: 'Error fetching users' });
      }
      res.status(200).json(results);
  });
});

app.post('/register', (req, res) => {
    const { username, email, password } = req.body;

    // Validate inputs
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Please provide username, email, and password' });
    }

    // Check if user already exists
    connection.query('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], (error, results, fields) => {
        if (error) {
            console.error('Error checking existing user: ' + error);
            return res.status(500).json({ error: 'Error registering user' });
        }
        if (results.length > 0) {
            return res.status(400).json({ error: 'User with this username or email already exists' });
        }

        // Hash password
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                console.error('Error hashing password: ' + err);
                return res.status(500).json({ error: 'Error registering user' });
            }
            const newUser = { username, email, password: hash };

            // Insert new user
            connection.query('INSERT INTO users SET ?', newUser, (error, results, fields) => {
                if (error) {
                    console.error('Error registering user: ' + error);
                    return res.status(500).json({ error: 'Error registering user' });
                }
                res.status(201).json({ message: 'User registered successfully' });
            });
        });
    });
});


// Login endpoint
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Check if user is already logged in (check session)
    if (req.session.userId) {
        return res.status(400).json({ error: 'User is already logged in' });
    }

    connection.query('SELECT * FROM users WHERE email = ?', [email], (error, results, fields) => {
        if (error) {
            console.error('Error logging in: ' + error);
            return res.status(500).json({ error: 'Error logging in' });
        }
        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const user = results[0];
        bcrypt.compare(password, user.password, (err, result) => {
            if (err || !result) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            // Set session for logged in user
            req.session.userId = user.id;

            res.status(200).json({ message: 'Login successful' });
        });
    });
});


// Start server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
