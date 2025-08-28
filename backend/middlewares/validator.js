const Joi = require('joi');

const signUpSchema = Joi.object({
    email: Joi.string()
        .min(5)
        .max(70)
        .required()
        .email({ tlds: { allow: ['com', 'net'] } })
        .messages({
            'string.email': 'Please enter a valid email address',
            'string.empty': 'Email is required',
        }),

    password: Joi.string()
        .min(6)
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*])[A-Za-z\\d!@#$%^&*]{6,}$'))
        .required()
        .messages({
            'string.empty': 'Password is required',
            'string.min': 'Password should have at least 6 characters',
            'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
        }),
});

const signInSchema = Joi.object({
    email: Joi.string()
        .min(5)
        .max(70)
        .required()
        .email({ tlds: { allow: ['com', 'net'] } })
        .messages({
            'string.email': 'Please enter a valid email address',
            'string.empty': 'Email is required',
        }),

    password: Joi.string()
        .min(6)
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*])[A-Za-z\\d!@#$%^&*]{6,}$'))
        .required()
        .messages({
            'string.empty': 'Password is required',
            'string.min': 'Password should have at least 6 characters',
            'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
        }),
});

const acceptCodeSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(70)
        .required()
        .email({
            tlds: { allow: ['com', 'net'] }
        }),
    providedCode: Joi.number()
})

const changePasswordSchema = Joi.object({
    newPassword: Joi.string()
        .required()
        .pattern(
            new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,30}$")
        )
        .messages({
            "string.empty": "New password is required",
            "string.min": "New password must be at least 6 characters long",
            "string.max": "New password must not exceed 30 characters",
            "string.pattern.base":
                "New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
        }),
        
    oldPassword: Joi.string()
        .required()
        .pattern(
            new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,30}$")
        )
        .messages({
            "string.empty": "Old password is required",
        }),
});


module.exports = { signUpSchema, signInSchema, acceptCodeSchema, changePasswordSchema };