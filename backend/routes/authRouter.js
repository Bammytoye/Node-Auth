const express = require('express');
const router = express.Router();

// Signup route
router.post('/signup', (req, res) => {
    res.json({ message: 'signup successful' });
});

// Signin route
router.post('/signin', (req, res) => {
    res.json({ message: 'signin successful' });
});

module.exports = router;
