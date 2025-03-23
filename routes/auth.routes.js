require('dotenv').config({ path: '../.env' });

const router = require('express').Router();

const User = require('../models/User.model.js');

const bcrypt = require('bcryptjs');

const SESSION_SECRET = process.env.SESSION_SECRET;


// HELPER TO SIGN COOKIES
const signCookies = require('../utils/signCookies.js');

// MIDDLEWARES TO GUARD ROUTES 
const { isLoggedIn, isLoggedOut, isAdmin } = require('../middlewares/route-guard.js');
// SIGN UP ROUTE

router.get('/signup', isLoggedOut, (req, res) => {
    res.render('auth/signup.hbs')
});

router.post('/signup', isLoggedOut, (req, res) => {
    console.log(req.body)
    const { name, email, password, isAdmin } = req.body

    // MAKE SURE USER FILLS ALL FIELDS
    if (!name || !email || !password || !isAdmin) {

        res.status(400).render('auth/signup.hbs', { errorMessage: 'Provide name, email,password and isAdminString' });
        return;
    }
    // MAKE SURE EMAIL HAS VALID FORMAT

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (!emailRegex.test(email)) {

        res.status(400).render('auth/signup.hbs', { errorMessage: 'Enter a valid email format.' });
        return;
    }

    // MAKE SURE PASSWORD IS AT LEAST 6 CHARS WITH UPPER, LOWER CASE AND NUMBER
    const passwordRegex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;

    if (!passwordRegex.test(password)) {
        res.status(400).render('auth/signup.hbs', { errorMessage: 'Password must have at least 6 characters and contain at least one number, one lowercase and one uppercase letter.' });
        return;
    }
    //CHECK IF EMAIL IS ALREADY REGISTERED.

    User.findOne({ email })
        .then((user) => {
            console.log('user from db:', user);
            if (user) {
                res.status(400).render('auth/signup.hbs', { errorMessage: 'This email is already registered.' })
                return;
            }
            const isAdminString = isAdmin === 'true' ? true : false;
            const salt = bcrypt.genSaltSync(10);
            const hash = bcrypt.hashSync(password, salt);
            return User.create({ name, email, password: hash, isAdmin: isAdminString });
        })
        .then((newUser) => {
            console.log('New user:', newUser)
            if (!newUser) {
                return;
            }
            res.status(201).redirect('/login');
        })
        .catch((err) => console.log('Error retrieving user:', err));

})

router.get('/login', isLoggedOut, (req, res) => {
    res.render('auth/login.hbs');
})

router.post('/login', isLoggedOut, (req, res) => {

    const { email, password } = req.body;

    // CHECK ALL FIELDS ARE FILLED

    if (!email || !password) {
        res.status(400).render('auth/login.hbs', { errorMessage: 'Provide email and password.' });
        return;
    }
    // CHECK IF USER EXISTS
    User.findOne({ email })
        .then((user) => {
            if (!user) {
                res.status(401).render('auth/login.hbs', { errorMessage: 'User not found' });
                return;
            } else if (bcrypt.compareSync(password, user.password)) {

                const id = user._id.toString();
                const signedValue = signCookies(id, SESSION_SECRET);
                // res.cookie('session', `${signedValue}`, { httpOnly: true });
                res.setHeader('Set-Cookie', `session=${signedValue}; HttpOnly; Path=/`)
                res.redirect('/user/profile');

            } else {
                res.status(400).render('auth/login.hbs', { errorMessage: 'Incorrect password' });
            }
        })
        .catch((err) => console.log("Error loggin in:", err));
})

router.get('/user/profile', isLoggedIn, (req, res) => {
    res.status(200).render('users/user-profile.hbs', { user: req.currentUser });

})
router.get('/admin/dashboard', isLoggedIn, isAdmin, (req, res) => {
    console.log('current user:', req.currentUser)
    res.status(200).render('admin/dashboard.hbs', { user: req.currentUser });

})
router.post('/logout', (req, res) => {
    res.clearCookie('session', { httpOnly: true });
    res.redirect('/login')


})
module.exports = router;