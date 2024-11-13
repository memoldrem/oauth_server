// server.js
const express = require('express');
const app = express();
const port = 3000;
const bcrypt = require('bcryptjs'); // we made it bcrypt js
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
require('dotenv').config(); // if statement for production mode?

const initializePassport = require('./config/passport-config')
initializePassport(passport, //*user email, user id*
  // find user thru email in database!!!! need arg
  // also pass in user id
  )

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));
app.use(flash());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}))
app.use(passport.initialize())
app.use(passport.session())


// Login pages
app.get('/', (req, res) => {
  res.render('login.ejs')
})

app.post('/', passport.authenticate({
  successRedirect: '/dashboard',
  failureRedirect: '/',
  failureFlash: true,
}))

// Register pages
app.get('/register', (req, res) => {
  res.render('register.ejs')
})

app.post('/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    // add to database!!!
    res.redirect('/')
  } catch {
    res.redirect('/register')
  }
})

// Success pages
app.get('/dashboard', checkAuthenticated, (req, res) => {
  res.render('dashboard.ejs')
})


function checkAuthenticated(req, res, next){ // middleware to check authentication!
  if(req.isAuthenticated()){
    return next();
  }
  res.redirect('/login');
}

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
