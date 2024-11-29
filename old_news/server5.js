var bodyParser = require('body-parser');
var express = require('express');
const session = require('express-session');
var oauthServer = require('express-oauth-server');
var util = require('util');
const flash = require('connect-flash');
require('dotenv').config();
const db = require('./model');
OauthClient = db.OauthClient;
const oauthModel = require('../config/oauth-model');





// Create an Express application.
var app = express();

// Add body parser.
app.set('view engine', 'ejs');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
const passport = require('passport');
const initializePassport = require('../config/passport-config');
initializePassport(passport); 

app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }, // Update secure: true for production
    })
  );
app.use(passport.initialize());
app.use(passport.session());

// Passport setup
require('../config/passport-config')(passport);

// Add OAuth server.
app.oauth = new oauthServer({
      model: require('../config/oauth-model'),
      grants: ['authorization_code', 'password', 'refresh_token'],
      debug: true, // Enable debugging
    });

app.get('/', (req, res) => res.render('welcome'));
app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  await User.create({ username, email, passwordHash: hashedPassword });
  res.redirect('/login');
});

// Post token.
app.post('/oauth/token', app.oauth.token());

// Get authorization.
app.get('/oauth/authorize', ensureAuthenticated, function(req, res) {

  return res.render('authorize', {
    client_id: req.query.client_id,
    redirect_uri: req.query.redirect_uri,
    client_secret: 'your-client-secret',
  });
});

// Post authorization.
app.post('/oauth/authorize', async (req, res, next) => {
    const { client_id, client_secret, redirect_uri, decision } = req.body;
    console.log('Authorization request received:', req.body);
    console.log('1')
   

    if (!client_id || !redirect_uri || !client_secret) {
      console.log('2')
        return res.status(400).send('Oauth step: Invalid client_id or redirect_uri');
    }

    if (decision === 'deny') {
      console.log('3')
        return res.send('oauth post step: access denied');
      }

      try {
        console.log('4')
        return app.oauth.authorize()(req, res, next);
      } catch (error) {
        console.log('5')
        console.error('Error in authorize():', error);
        return res.status(500).send('OAuth authorization failed.');
      }
});

// Get login.
app.get('/login', (req, res) => {
    const { client_id, redirect_uri, state } = req.query;
    client_secret = 'your-client-secret';
    console.log('got login')

    if (!client_id || !redirect_uri) {
      return res.status(400).send('Invalid client_id or redirect_uri');
    }
   
  
    res.render('login.ejs', { client_id, redirect_uri, client_secret, state });
});

// Post login.
app.post('/login', passport.authenticate('local', { failureRedirect: '/login', failureFlash: true }), (req, res) => {
    
    const { client_id, redirect_uri, state } = req.body;

        if (!client_id || !redirect_uri) {
            return res.status(400).send('Invalid client_id or redirect_uri');
        }

        // Redirect to `/oauth/authorize` with query parameters
        const path = '/oauth/authorize';
        console.log("post login")
     
        const redirectUrl = `${path}?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}`;


        console.log('Redirecting to:', redirectUrl);
        return res.redirect(redirectUrl);
});

// Get secret.
app.get('/secret', app.oauth.authenticate(), function(req, res) {
  // Will require a valid access_token.
  res.send('Secret area');
});

app.get('/public', function(req, res) {
  // Does not require an access_token.
  res.send('Public area');
});


function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.send('user not authenticated')
  }

// Start listening for requests.
db.sequelize.sync({ force: false }).then(async () => {
    const existingClient = await OauthClient.findOne({ where: { clientId: '1' } });
    if (!existingClient) {
      // Add the static client to the database
      await OauthClient.create({
        clientId: '1',
        clientSecret: 'your-client-secret',
        redirectUri: 'http://your-redirect-uri.com',
      });
      console.log('Static client added to database');
    } else {
      console.log('Static client already exists');
    }
  
    app.listen(3001, () => console.log('Server running on http://localhost:3001'));
  }).catch((err) => console.error('Error syncing models:', err));
