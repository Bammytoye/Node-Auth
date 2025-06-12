const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, 'Email is required, Please'],
        unique: [true, 'Email must be unique, Thanks'],
        lowercase: true,
        trim: true,
        minLength: [5, 'Email must have 5 characters!'],
    },

    password: {
        type: String,
        required: [true, 'Password must be provided...'],
        trim: true,
        select: false,
    },

    verified: {
        type: Boolean,
        default: false,
    },

    verificationCode: {
        type: String,
        select: false,
    },

    verificationCodeValidation: {
        type: Number,
        select: false,
    },

    forgotPasswordCode: {
        type: String,
        select: false,
    },

    forgotPasswordCodeValidation: {
        type: Number,
        select: false,
    },
}, {
    timestamps: true,
});

const User = mongoose.model('User', userSchema);

export default User;
