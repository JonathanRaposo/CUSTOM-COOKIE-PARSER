require('dotenv').config({ path: '../.env' });

const router = require('express').Router();

const User = require('../models/User.model.js');

const bcrypt = require('bcryptjs');

const SECRET_KEY = process.env.SECRET_KEY;


// HELPER TO SIGN COOKIES
const signCookies = require('../utils/signCookies.js');

// MIDDLEWARES TO GUARD ROUTES 
const { isLoggedIn, isLoggedOut } = require('../middlewares/route-guard.js');
// SIGN UP ROUTE

router.get('/signup', isLoggedOut, (req, res) => {
    res.render('auth/signup.hbs')
});

router.post('/signup', isLoggedOut, (req, res) => {

    const { name, email, password } = req.body

    // MAKE SURE USER FILLS ALL FIELDS
    if (!name || !email || !password) {

        res.status(400).render('auth/signup.hbs', { errorMessage: 'Provide name, email and password' });
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
            const salt = bcrypt.genSaltSync(10);
            const hash = bcrypt.hashSync(password, salt);
            return User.create({ name, email, password: hash });
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
            console.log('user:', user)
            if (!user) {
                res.status(401).render('auth/login.hbs', { errorMessage: 'User not found' });
                return;
            } else if (bcrypt.compareSync(password, user.password)) {
                const id = user._id.toString();
                const signedValue = signCookies(id, SECRET_KEY);
                console.log('signature:', signedValue);
                res.cookie('session', `${signedValue}`, { httpOnly: true, maxAge: 3600000 });
                res.cookie('theme', 'dark', { maxAge: 3600000 });
                res.cookie('role', 'admin', { maxAge: 360000 });
                res.redirect('/userProfile');

            } else {
                res.status(400).render('auth/login.hbs', { errorMessage: 'Incorrect password' });
            }
        })
        .catch((err) => console.log("Error loggin in:", err));
})

router.get('/userProfile', isLoggedIn, (req, res) => {
    const id = req.signedCookies.session;
    const { theme } = req.cookies;

    User.findById(id)
        .then((user) => {
            const { name } = user;
            res.status(200).render('users/user-profile.hbs', { user: { name, theme } })
        })
        .catch((err) => console.log('Error retrieving user: ', err));

})
router.post('/logout', isLoggedIn, (req, res) => {
    res.clearCookie('session', { httpOnly: true });
    res.clearCookie('theme')
    res.clearCookie('role')
    res.redirect('/login')

})
module.exports = router;