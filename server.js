const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();

// Middleware
app.use(express.json());
app.use(cors()); // Enable CORS for all origins

// Initialize the server
const initializeDbAndServer = () => {
    try {
        // Start the server
        app.listen(4040, () => {
            console.log('Server Running at http://localhost:4040/');
        });
    } catch (error) {
        console.error(`Server Initialization Error: ${error.message}`);
        process.exit(1);
    }
    
    console.log('Server Initialization done');
};

// Routes
app.get('/', (req, res) => {
    try {
        res.json({ message: 'Server is running at 5000' });
    } catch (err) {
        console.error('Error handling request:', err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Start the server
initializeDbAndServer();
