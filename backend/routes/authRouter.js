const express = require('express');
const router = express.Router();
const { signUp, signIn, logOut, sendVerificationCode } = require('../controllers/authController')


router.post('/signup', signUp); // Register a user
router.post('/signin', signIn); // Login a user
router.post('/logout', logOut); // Logout endpoint
router.patch('/send-verification-code', sendVerificationCode); // Send email/SMS verification



module.exports = router;