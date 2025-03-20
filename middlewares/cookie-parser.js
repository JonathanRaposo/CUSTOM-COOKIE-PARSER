

const crypto = require('crypto');


function cookieParser(secretKey = null) {
    return (req, res, next) => {

        req.cookies = {};
        req.signedCookies = {};

        if (!req.headers.cookie) {
            next();
            return;
        }
        const cookies = {}

        const cookiePairs = req.headers.cookie.split('; ');

        for (let cookie of cookiePairs) {
            const [key, value] = cookie.split('=');
            cookies[key] = decodeURIComponent(value);
        }

        for (let key in cookies) {

            if (typeof secretKey === 'string' && cookies[key].includes('s:')) {

                const [payload, hash] = cookies[key].slice(2).split('.');
                const expectedSignature = crypto.createHmac('sha256', secretKey).update(payload).digest('base64url');

                if (expectedSignature === hash) {
                    req.signedCookies[key] = payload;
                } else {
                    req.cookies[key] = cookies[key]
                }


            }
            else if (key === 'Path' || key === 'HttpOnly' || key === 'Max-Age' || key === 'Secure' || key === 'SameSite' || key === 'Domain') {
                continue;
            } else {
                req.cookies[key] = cookies[key];
            }

        }
        next();
    }

}
module.exports = cookieParser;






// console.log(request)