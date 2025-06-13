const express = require('express');
const router = express.Router();
const signUp = require('../controllers/authController')


// Signup route
router.post('/signup', (req, res) => {
    res.json({ message: 'signup successful' });
});

// Signin route
router.post('/signin', signUp);

module.exports = router;
