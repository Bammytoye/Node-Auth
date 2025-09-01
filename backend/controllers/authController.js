const jwt = require('jsonwebtoken');
const { signUpSchema, signInSchema, acceptCodeSchema, changePasswordSchema, acceptForgotPasswordCodeSchema } = require("../middlewares/validator");
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

        res.cookie('Authorization', 'Bearer ' + token, {
            expires: new Date(Date.now() +
                8 * 3600000),
            httpOnly: process.env.NODE_ENV === 'production',
            secure: process.env.NODE_ENV === 'production',
        }).json({
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
    res.clearCookie("Authorization", {
        httpOnly: true,
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production"
    });

    return res.status(200).json({
        success: true,
        message: "User logged out successfully"
    });
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
    const { email, providedCode } = req.body;

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

        if (existingUser.verified) {
            return res.status(400).json({ success: false, message: 'User already verified' })
        }

        // If verification code is not set or validation time is not set, we assume the user has not been verified yet
        if (!existingUser.verificationCode || !existingUser.verificationCodeValidation) {
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
    try {
        console.log("Incoming body:", req.body);

        // 1. Validate body presence
        if (!req.body || !req.body.oldPassword || !req.body.newPassword) {
            return res.status(400).json({
                success: false,
                message: "oldPassword and newPassword are required",
            });
        }

        const { oldPassword, newPassword } = req.body;

        // 2. Validate with Joi schema
        const { error } = changePasswordSchema.validate({ oldPassword, newPassword });
        if (error) {
            return res
                .status(401)
                .json({ success: false, message: error.details[0].message });
        }

        // 3. Ensure req.user exists (authMiddleware should set this)
        if (!req.user || !req.user.userId) {
            return res
                .status(401)
                .json({ success: false, message: "Unauthorized: No user context" });
        }

        const { userId } = req.user;

        // 4. Fetch user from DB (always get latest verification + password)
        const existingUser = await usersModel
            .findOne({ _id: userId })
            .select("+password");

        if (!existingUser) {
            return res
                .status(401)
                .json({ success: false, message: "User does not exist" });
        }

        // 5. Check verification from DB (not from stale JWT)
        if (!existingUser.verified) {
            return res
                .status(401)
                .json({ success: false, message: "User is not verified" });
        }

        // 6. Check old password correctness
        const isOldPasswordValid = await hashingPasswordValidation(
            oldPassword,
            existingUser.password
        );

        if (!isOldPasswordValid) {
            return res
                .status(401)
                .json({ success: false, message: "Old password is incorrect" });
        }

        // 7. Hash new password and save
        const hashedPassword = await hashingPassword(newPassword, 12);
        existingUser.password = hashedPassword;
        await existingUser.save();

        return res
            .status(200)
            .json({ success: true, message: "Password changed successfully" });
    } catch (error) {
        console.error("Error in changePassword:", error);
        return res
            .status(500)
            .json({ success: false, message: "Something went wrong" });
    }
}

async function sendForgotPasswordCode(req, res, next) {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required",
            });
        }

        // 1. Find user by email
        const existingUser = await usersModel.findOne({ email });
        if (!existingUser) {
            return res.status(404).json({
                success: false,
                message: "User with this email does not exist",
            });
        }

        const codeValue = Math.floor(Math.random() * 1000000).toString();
        let info = await transport.sendMail({
            from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
            to: existingUser.email,
            subject: 'Forgot Password Code',
            html: '<h1>' + codeValue + '</h1>',
        })

        if (info.accepted[0] === existingUser.email) {
            const hashedCodeValue = hmacProcess(
                codeValue,
                process.env.HMAC_VERIFICATION_CODE_SECRET
            );
            existingUser.forgotPasswordCode = hashedCodeValue;
            existingUser.forgotPasswordCodeValidation = Date.now();
            await existingUser.save();
            return res.status(200).json({ success: true, message: 'code sent successfully' })
        }
        return res.status(400).json({ success: false, message: "Password reset code could not be sent", });

    } catch (error) {
        console.error("Error in sendForgotPasswordCode:", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
}

const bcrypt = require("bcryptjs");

async function verifyForgotPasswordCode(req, res, next) {
    const { email, providedCode, newPassword } = req.body;

    try {
        // ✅ Validate input
        const { error } = acceptForgotPasswordCodeSchema.validate({
            email,
            providedCode,
            newPassword,
        });

        if (error) {
            return res.status(401).json({
                success: false,
                message: error.details[0].message,
            });
        }

        const codeValue = providedCode.toString();

        // ✅ Find user
        const existingUser = await usersModel.findOne({ email }).select(
            "+forgotPasswordCode +forgotPasswordCodeValidation"
        );

        if (!existingUser) {
            return res.status(401).json({
                success: false,
                message: "User does not exist!",
            });
        }

        if (
            !existingUser.forgotPasswordCode ||
            !existingUser.forgotPasswordCodeValidation
        ) {
            return res.status(400).json({
                success: false,
                message: "Something is wrong with the code!",
            });
        }

        // ✅ Expiry check (5 minutes)
        if (Date.now() - existingUser.forgotPasswordCodeValidation > 5 * 60 * 1000) {
            return res.status(400).json({
                success: false,
                message: "Code has expired!",
            });
        }

        // ✅ Hash provided code and compare
        const hashedCodeValue = hmacProcess(
            codeValue,
            process.env.HMAC_VERIFICATION_CODE_SECRET
        );

        if (hashedCodeValue !== existingUser.forgotPasswordCode) {
            return res.status(400).json({
                success: false,
                message: "Invalid verification code!",
            });
        }

        // ✅ Code is valid → reset password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        existingUser.password = hashedPassword;
        existingUser.forgotPasswordCode = undefined;
        existingUser.forgotPasswordCodeValidation = undefined;

        await existingUser.save();

        return res.status(200).json({
            success: true,
            message: "Password has been reset successfully!",
        });
    } catch (error) {
        console.error("Error in verifyForgotPasswordCode:", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
}



module.exports = { signUp, signIn, logOut, sendVerificationCode, verifyVerificationCode, changePassword, verifyForgotPasswordCode, sendForgotPasswordCode, };