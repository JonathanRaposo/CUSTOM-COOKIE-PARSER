
const crypto = require('crypto');

function signCookies(value, secretKey) {
    return 's:' + value + '.' + crypto.createHmac('sha256', secretKey).update(value).digest('base64url');
}

module.exports = signCookies;