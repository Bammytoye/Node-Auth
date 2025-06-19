const bcrypt = require('bcryptjs');  
const { createHmac } = require('crypto');


const hashingPassword = async (password) => {
    const salt = await bcrypt.hash(password, 10);
    return salt;
};

const hashingPasswordValidation = async (password, hashedValue) => {
    const result = await bcrypt.compare(password, hashedValue);
    return result;
};

const hmacPassword = async (value, key) => {
    const result = createHmac('sha256', key).update(value).digest('hex');
    return result;
}

module.exports = { hashingPassword, hashingPasswordValidation, hmacPassword };
