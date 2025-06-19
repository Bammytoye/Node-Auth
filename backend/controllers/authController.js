const jwt = require('jsonwebtoken');
const { signUpSchema, signInSchema } = require("../middlewares/validator");
const usersModel = require("../models/usersModel");
const { hashingPassword, hashingPasswordValidation } = require("../utils/hashingPassword");

async function signUp(req, res) {
    const { email, password } = req.body;

    try {
        const { error, value } = signUpSchema.validate({ email, password });

        if (error) {
            return res.status(401).json({ success: false, message: error.details[0].message });
        }

        const existingUser = await usersModel.findOne({ email });

        if (existingUser) {
            return res.status(401).json({ success: false, message: 'User already exists' });
        }

        const hashedPassword = await hashingPassword(password);
        const user = await usersModel.create({ email, password: hashedPassword });

        res.status(201).json({ success: true, message: 'User created successfully', user });

    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}

async function signIn(req, res) {
    const { email, password } = req.body;

    try {
        const { error, value } = signInSchema.validate({ email, password });

        if (error) {
            return res.status(401).json({ success: false, message: error.details[0].message });
        }

        const user = await usersModel.findOne({ email }).select('password');

        if (!user) {
            return res.status(401).json({ success: false, message: 'User does not exist' });
        }

        const result = await hashingPasswordValidation(password, user.password);
        if (!result) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign({ 
            userId: user._id,
            email: user.email, 
            verified: user.verified, 
        }, process.env.JWT_SECRET);

        res.cookie('Authorization', 'Bearer ' + token, { expires: new Date(Date.now() + 
            8 * 3600000),
            httpOnly: process.env.NODE_ENV === 'production',
            secure: process.env.NODE_ENV === 'production',
        }).json ({
            success: true,
            token,
            message: 'User logged in successfully'
        });
        
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}

module.exports = { signUp, signIn };
