require('dotenv').config({ path: '../.env' });

const User = require('../models/User.model.js');

require('../db/index.js')(process.env.MONGODB_URI)

function isLoggedIn(req, res, next) {
    if (!req.signedCookies.session) {
        return res.redirect('/login');

    }
    const userId = req.signedCookies.session;
    User.findById(userId)
        .then((user) => {
            const userId = user._id.toString();
            const { name, email, isAdmin } = user;
            const payload = { userId, name, email, isAdmin };
            req.currentUser = payload;
            next();
        })
        .catch((err) => console.log('Error retrieving user:', err))

}
function isLoggedOut(req, res, next) {
    if (req.signedCookies.session) {
        return res.redirect('/'); // If user is logged in, stop and redirect to home page
    }
    next();// If user is not logged in, continue processing the request
}

function isAdmin(req, res, next) {
    if (req.currentUser && req.currentUser.isAdmin) {
        return next();
    }
    res.status(403).render('admin/403-page.hbs');
}
module.exports = { isLoggedIn, isLoggedOut, isAdmin };