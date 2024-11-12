// server.js
const express = require('express');
const app = express();
const port = 3000;
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
require('dotenv').config(); // if statement for production mode?

const initializePassport = require('./passport-config')
initializePassport(passport, //*user email, user id*
  // find user thru email in database!!!! need arg
  // also pass in user id
  )

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}))
app.use(flash)
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}))
app.use(passport.initialize())
app.use(passport.session())

app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs')
})

app.get('/login', (req, res) => {
  res.render('login.ejs')
})

app.post('/login', passport.authenticate({
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true,

}))

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


function checkAuthenticated(req, res, next){
  if(req.isAuthenticated()){
    return next();
  }
  res.redirect('/login');
}

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
