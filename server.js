const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const bcryptjs = require('bcryptjs');
const bodyParser = require('body-parser');
const path = require('path');
const { check, validationResult } = require('express-validator');

// Initialize
const app = express();

// Configure
app.use(express.static(__dirname));
app.use(express.json());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: true }));

// Configure session
app.use(session({
    secret: 'your_secret_key', // Change this to a real secret key
    resave: false,
    saveUninitialized: true
}));

// Connection
const connection = mysql.createConnection({
    host: 'localhost',
    port: 3306,
    user: 'root',
    password: 'newpassword',
    database: 'expense_tracker'
});

connection.connect((err) => {
    if (err) {
        console.error('Error occurred while connecting to the DB server: ' + err.stack);
        return;
    }
    console.log('DB server connected successfully');
});

// Routes
app.get('/register', (request, response) => {
    response.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/login', (request, response) => {
    response.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/plp/users/registration', [
    // Validation
    check('email')
        .isEmail().withMessage('Provide a valid email address.')
        .custom(async (value) => {
            return new Promise((resolve, reject) => {
                User.getUserByEmail(value, (err, user) => {
                    if (err) {
                        console.error('Database error:', err);
                        return reject(new Error('Server error occurred while checking email.'));
                    }
                    if (user && user.length > 0) {
                        return reject(new Error('Email already exists.'));
                    }
                    resolve(true);
                });
            });
        }),
    check('username')
        .isAlphanumeric().withMessage('Invalid username. Provide alphanumeric values.')
        .custom(async (value) => {
            return new Promise((resolve, reject) => {
                User.getUserByUsername(value.trim(), (err, user) => {
                    if (err) {
                        console.error('Database error:', err);
                        return reject(new Error('Server error occurred while checking username.'));
                    }
                    if (user && user.length > 0) {
                        return reject(new Error('Username already in use.'));
                    }
                    resolve(true);
                });
            });
        })
], async (request, response) => {
    // Validation
    const errors = validationResult(request);
    if (!errors.isEmpty()) {
        return response.status(400).json({ errors: errors.array() });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcryptjs.hash(request.body.password, saltRounds);

    // User object
    const newUser = {
        full_name: request.body.full_name,
        email: request.body.email,
        username: request.body.username.trim(),
        password: hashedPassword
    };

    // Save user
    User.createUser(newUser, (error) => {
        if (error) {
            console.error('An error occurred while saving the record: ' + error.message);
            return response.status(500).json({ error: error.message });
        }
        console.log('New user record saved!');
        response.status(201).send('Registration successful!');
    });
});

app.post('/plp/users/login', [
    // Validation
    check('username').notEmpty().withMessage('Username is required.'),
    check('password').notEmpty().withMessage('Password is required.')
], async (request, response) => {
    const errors = validationResult(request);
    if (!errors.isEmpty()) {
        return response.status(400).json({ errors: errors.array() });
    }

    const { username, password } = request.body;

    User.getUserByUsername(username, async (err, users) => {
        if (err) {
            console.error('Database error:', err);
            return response.status(500).json({ error: 'Server error occurred while checking username.' });
        }

        if (users.length === 0) {
            return response.status(401).json({ error: 'Invalid username or password.' });
        }

        const user = users[0];
        const match = await bcryptjs.compare(password, user.password);

        if (match) {
            // Set session
            request.session.userId = user.id;
            response.status(200).json({ message: 'Login successful!' });
        } else {
            response.status(401).json({ error: 'Invalid username or password.' });
        }
    });
});

app.get('/plp/users/logout', (request, response) => {
    request.session.destroy((err) => {
        if (err) {
            console.error('Error occurred during logout:', err);
            return response.status(500).json({ error: 'Server error occurred during logout.' });
        }
        response.status(200).send('Logout successful!');
    });
});

// User object
const User = {
    tableName: 'users',
    createUser: function(newUser, callback) {
        connection.query('INSERT INTO ' + this.tableName + ' SET ?', newUser, callback);
    },
    getUserByEmail: function(email, callback) {
        connection.query('SELECT * FROM ' + this.tableName + ' WHERE email = ?', [email], callback);
    },
    getUserByUsername: function(username, callback) {
        connection.query('SELECT * FROM ' + this.tableName + ' WHERE username = ?', [username], callback);
    }
};

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
