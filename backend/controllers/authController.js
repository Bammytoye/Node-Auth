const { signUpSchema } = require("../middlewares/validator");
const usersModel = require("../models/usersModel");
const { hashingPassword } = require("../utils/hashingPassword");

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

module.exports = { signUp };
