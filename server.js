const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());

const databasePath = path.join(__dirname, 'user.db');
const jwtSecret = crypto.randomBytes(64).toString('hex');

let db = new sqlite3.Database(databasePath, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        createTables();
    }
});

app.use(
    cors({
        origin: 'http://localhost:3000',
    })
);

const createTables = () => {
    const createUserTable = `
        CREATE TABLE IF NOT EXISTS userDetails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) NOT NULL UNIQUE,
            email VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL
        )`;
    const createTodoTable = `
        CREATE TABLE IF NOT EXISTS todo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task TEXT NOT NULL,
            status VARCHAR(255) NOT NULL,
            userId INTEGER NOT NULL
        )`;

    db.run(createUserTable, (err) => {
        if (err) {
            console.error('Error creating userDetails table:', err.message);
        } else {
            console.log('UserDetails table created successfully.');
        }
    });

    db.run(createTodoTable, (err) => {
        if (err) {
            console.error('Error creating todo table:', err.message);
        } else {
            console.log('Todo table created successfully.');
        }
    });
};

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Helper function to validate required fields
const validateFields = (fields) => {
    return fields.every((field) => field !== undefined && field !== null && field !== '');
};

// Routes
app.post('/', (req, res) => {
    const { name, password } = req.body;
    if (!validateFields([name, password])) {
        return res.status(400).json({ error: 'Invalid request: Missing username or password' });
    }
    const query = `SELECT * FROM userDetails WHERE username = ?`;
    db.get(query, [name], (err, user) => {
        if (err) {
            console.error('Error fetching user:', err.message);
            return res.status(500).json({ error: 'Failed to authenticate user' });
        }
        if (user && bcrypt.compareSync(password, user.password)) {
            const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });
            res.status(200).json({ message: 'Successfully logged in', token });
        } else {
            res.status(401).json({ error: 'Invalid username or password' });
        }
    });
});

app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    if (!validateFields([username, email, password])) {
        return res.status(400).json({ error: 'Invalid request: Missing username, email, or password' });
    }
    const hashedPassword = bcrypt.hashSync(password, 10);
    const selectQuery = `SELECT username FROM userDetails WHERE username = ? OR email = ?`;
    db.get(selectQuery, [username, email], (err, user) => {
        if (err) {
            console.error('Error fetching user:', err.message);
            return res.status(500).json({ error: 'Failed to register user' });
        }
        if (!user) {
            const insertQuery = `INSERT INTO userDetails(username, email, password) VALUES (?, ?, ?)`;
            db.run(insertQuery, [username, email, hashedPassword], function (err) {
                if (err) {
                    console.error('Error registering user:', err.message);
                    return res.status(500).json({ error: 'Failed to register user' });
                }
                res.status(200).json({ message: 'New user registered successfully' });
            });
        } else {
            res.status(400).json({ error: 'User already exists' });
        }
    });
});

app.get('/userDetails', (req, res) => {
    const query = `SELECT * FROM userDetails`;
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Error fetching user details:', err.message);
            return res.status(500).json({ error: 'Failed to fetch user details' });
        }
        res.status(200).json(rows);
    });
});

app.post('/todoPost/:user', authenticateToken, (req, res) => {
    const user = req.params.user;
    const { task, status } = req.body;
    if (!validateFields([task, status])) {
        return res.status(400).json({ error: 'Invalid request: Missing task or status' });
    }
    try {
        const addTodoQuery = `INSERT INTO todo (task, status, userId) VALUES(?, ?, ?)`;
        const result = db.prepare(addTodoQuery).run(task, status, user);
        res.status(200).json({ message: 'Todo added successfully', id: result.lastInsertRowid });
    } catch (error) {
        console.error('Error adding todo:', error);
        res.status(500).json({ error: 'Failed to add todo' });
    }
});

app.get('/todoList/:userId', authenticateToken, (req, res) => {
    const userId = req.params.userId;
    try {
        const getTodoListQuery = `SELECT * FROM todo WHERE userId = ?`;
        const todos = db.prepare(getTodoListQuery).all(userId);
        res.status(200).json(todos);
    } catch (error) {
        console.error('Error fetching todo list:', error);
        res.status(500).json({ error: 'Failed to fetch todo list' });
    }
});

app.listen(4040, () => {
    console.log('Server Running at http://localhost:4040/');
});