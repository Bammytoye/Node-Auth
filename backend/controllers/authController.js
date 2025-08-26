const jwt = require('jsonwebtoken');
const { signUpSchema, signInSchema, acceptCodeSchema } = require("../middlewares/validator");
const usersModel = require("../models/usersModel");
const { hashingPassword, hashingPasswordValidation } = require("../utils/hashingPassword");
const { transport } = require('../middlewares/sendMail');
const hmacProcess = (value, key) => createHmac('sha256', key).update(value).digest('hex');
const { createHmac } = require('crypto');

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
        }, process.env.JWT_SECRET, {
            expiresIn: '1h',
        });

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

async function logOut(req, res) {
    res.clearCookie('Authorization')
    .status(200)
    .json({ success: true, message: 'User logged out successfully' });
}

async function sendVerificationCode(req, res, next) {
    const { email } = req.body;

    try {
        const existingUser = await usersModel.findOne({ email });

        if (!existingUser) {
            return res.status(404)
            .json({ success: false, message: 'User does not exist' });
        }

        if (existingUser.verified) {
            return res.status(400)
            .json({ success: false, message: 'User already verified' });
        }

        const codeValue = Math.floor(100000 + Math.random() * 900000).toString(); // always 6 digits

        let info = await transport.sendMail({
            from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
            to: existingUser.email,
            subject: 'Verification Code',
            text: `Your verification code is ${codeValue}`,
        })

        if (info.accepted[0] === existingUser.email) {
            const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET) 
            existingUser.verificationCode = hashedCodeValue;
            existingUser.verificationCodeValidation = Date.now()
            await existingUser.save();
            return res.status(200) 
            .json({ success: true, message: 'Verification code sent successfully' });
        }
            res.status(400).json({ success: false, message: 'Verification code not sent' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}

async function verifyVerificationCode(req, res, next) {
    const { email , providedCode } = req.body;

    try {
        const { error, value } = acceptCodeSchema.validate({ email, providedCode });

        if (error) {
            return res.status(401).json({ success: false, message: error.details[0].message });
        }

        const codeValue = providedCode.toString();
        const existingUser = await usersModel.findOne({ email }).select(' +verificationCode +verificationCodeValidation');

        if (!existingUser) {
            return res.status(401)
            .json({ success: false, message: 'User does not exist' });
        }

        if(existingUser.verified) {
            return res.status(400).json({success: false, message: 'User already verified'})
        }

        // If verification code is not set or validation time is not set, we assume the user has not been verified yet
        if(!existingUser.verificationCode || !existingUser.verificationCodeValidation) {
            return res.status(400).json({ success: false, message: 'Something is wrong with the code!' });
        }

        if (Date.now() - existingUser.verificationCodeValidation > 600000) {
            return res.status(400).json({ success: false, message: 'Verification code expired' });
        }

        const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);

        if (hashedCodeValue === existingUser.verificationCode) {
            existingUser.verified = true;
            existingUser.verificationCode = undefined;
            existingUser.verificationCodeValidation = undefined;
            await existingUser.save();
            return res.status(200).json({ success: true, message: 'Your account has been verified' }) 
        }
            return res.status(400).json({ success: false, message: 'unexpected occurred' }) 
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}   

async function changePassword(req, res, next) {
    const { userId, verified } = req.user;
    const { oldPassword, newPassword} = req.body;

    try {

    } catch (error) {
        console.log(error)
    }
}

module.exports = { signUp, signIn, logOut, sendVerificationCode, verifyVerificationCode, changePassword };