const bcrypt = require('bcryptjs');  

const hashingPassword = async (password) => {
    const salt = await bcrypt.hash(password, 10);
    return salt;
};

const hashingPasswordValidation = async (password, hashedValue) => {
    const result = await bcrypt.compare(password, hashedValue);
    return result;
};

module.exports = { hashingPassword, hashingPasswordValidation };
