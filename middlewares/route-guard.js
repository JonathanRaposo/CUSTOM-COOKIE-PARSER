
function isLoggedIn(req, res, next) {

    if (!req.signedCookies.session) {
        return res.redirect('/login');

    }
    next();
}
function isLoggedOut(req, res, next) {
    if (req.signedCookies.session) {
        return res.redirect('/');
    }
    next();
}
module.exports = { isLoggedIn, isLoggedOut };