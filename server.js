const serverlessExpress = require('@vendia/serverless-express');
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

let db = null;
const databasePath = path.join(__dirname, 'user.db');
const jwtSecret = crypto.randomBytes(64).toString('hex');

const app = express();
app.use(express.json());
app.use(cors({ origin: 'http://localhost:3000' }));

const createTables = () => {
    try {
        db.prepare(`
            CREATE TABLE IF NOT EXISTS userDetails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(255) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL
            )
        `).run();

        db.prepare(`
            CREATE TABLE IF NOT EXISTS todo (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task TEXT NOT NULL,
                status VARCHAR(255) NOT NULL,
                userId INTEGER NOT NULL
            )
        `).run();
    } catch (error) {
        console.error('Error creating tables:', error);
        throw new Error('Database initialization failed');
    }
};

const initializeDatabase = () => {
    try {
        db = new Database(databasePath, { verbose: console.log });
        createTables();
    } catch (error) {
        console.error(`DB Error: ${error.message}`);
        throw new Error('Database initialization failed');
    }
};

initializeDatabase();

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
    try {
        const query = `SELECT * FROM userDetails WHERE username = ?`;
        const user = db.prepare(query).get(name);

        if (user && bcrypt.compareSync(password, user.password)) {
            const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });
            res.status(200).json({ message: 'Successfully logged in', token });
        } else {
            res.status(401).json({ error: 'Invalid username or password' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Failed to authenticate user' });
    }
});

app.get('/', (req, res) => {
    res.status(200).json({ message: 'You are on the home page' });
});

app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    if (!validateFields([username, email, password])) {
        return res.status(400).json({ error: 'Invalid request: Missing username, email, or password' });
    }
    try {
        const hashedPassword = bcrypt.hashSync(password, 10);
        const selectUserQuery = `SELECT username FROM userDetails WHERE username = ? OR email = ?`;
        const dbUser = db.prepare(selectUserQuery).get(username, email);

        if (!dbUser) {
            const newRegisterQuery = `INSERT INTO userDetails(username, email, password) VALUES (?, ?, ?)`;
            db.prepare(newRegisterQuery).run(username, email, hashedPassword);
            res.status(200).json({ message: 'New user registered successfully' });
        } else {
            res.status(400).json({ error: 'User already exists' });
        }
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

app.get('/userDetails', (req, res) => {
    try {
        const allUsersQuery = `SELECT * FROM userDetails`;
        const users = db.prepare(allUsersQuery).all();
        res.status(200).json(users);
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ error: 'Failed to fetch user details' });
    }
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


module.exports.handler = serverlessExpress({ app });