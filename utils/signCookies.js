
const crypto = require('crypto');

function signCookies(value, secret) {
    
    if (typeof value !== 'string') {
        throw new TypeError('Cookie value Must be a string')
    }
    return 's:' + value + '.' + crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

module.exports = signCookies;