const { hash } = require('bcryptjs');

const hashingPassword = async (password) => {
    const salt = await hash(password, 10);
    return salt;
};

module.exports = { hashingPassword };
