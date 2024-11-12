// server.js
const express = require('express');
const app = express();
const port = 3000;
const bcrypt = require('bcrypt');
const passport = require('passport');

const initializePassport = require('./passport-config')
initializePassport(passport)

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}))

app.get('/', (req, res) => {
  res.render('index.ejs')
})

app.get('/login', (req, res) => {
  res.render('login.ejs')
})

app.post('/login', (req, res) => {

})

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

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
