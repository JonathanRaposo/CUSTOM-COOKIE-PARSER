require('dotenv').config();
const express = require('express');
const MONGODB_URI = process.env.MONGODB_URI;
const SECRET_KEY = process.env.SECRET_KEY;
// CONNECT TO DATABASE

require('./db/index.js')(MONGODB_URI);

const app = express();

// SET UP MIDDLEWARES
require('./config/index.js')(app);

// CUSTOM COOKIE PARSER
const cookieParser = require('./middlewares/cookie-parser.js')
app.use(cookieParser(SECRET_KEY))

// ROUTES HERE

const indexRouter = require('./routes/index.js');
app.use('/', indexRouter);

const authRouter = require('./routes/auth.routes.js');
app.use('/', authRouter);


// ERROR HANDLING MIDDLEWARE
app.use((req, res, next) => {
    res.status(404).render('not-found.hbs');
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`))

