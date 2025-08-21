const express = require('express');
const router = express.Router();
const { signUp, signIn, logOut, sendVerificationCode, verifyVerificationCode } = require('../controllers/authController');
const { identifier } = require('../middlewares/identification');


router.post('/signup', signUp); // Register a user
router.post('/signin', signIn); // Login a user
router.post('/logout', identifier, logOut); // Logout endpoint
router.patch('/send-verification-code', identifier, sendVerificationCode); // Send email/SMS verification
router.patch('/verify-verification-code', identifier, verifyVerificationCode); // confirm code verification



module.exports = router;