
const crypto = require('crypto');

function cookieParser(secret = undefined) {
    return (req, res, next) => {

        if (typeof secret === 'object') {
            throw new TypeError('Secret string must be provided but got an object.')
        }
        req.secret = secret;
        req.cookies = {};
        req.signedCookies = {};

        if (!req.headers.cookie) {
            return next();
        }

        const cookies = {};

        const cookiePairs = req.headers.cookie.split('; ');
        for (const cookie of cookiePairs) {
            const [key, value] = cookie.trim().split('=');
            cookies[key] = decodeURIComponent(value);
        }

        for (const pairs of Object.entries(cookies)) {
            const [key, value] = pairs;
            if (typeof secret === 'string' && value.includes('s:')) {
                const [payload, hash] = value.slice(2).split('.');

                const expectedSignature = crypto
                    .createHmac('sha256', secret)
                    .update(payload)
                    .digest('base64url');

                if (hash === expectedSignature) {
                    req.signedCookies[key] = payload;
                }
                else {
                    req.cookies[key] = value;
                }
            }
        
            else {
                req.cookies[key] = value;
            }

        };
        next();

    }
}

module.exports = cookieParser;
