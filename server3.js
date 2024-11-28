const express = require('express');
const oauth2orize = require('oauth2orize');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const db = require('./models');
const { randomBytes } = require('crypto');
const dotenv = require('dotenv');
const helmet = require('helmet');
const flash = require('express-flash');
const initializePassport = require('./config/passport-config');

dotenv.config();

const app = express();
const User = db.User;
const Client = db.Client;
const AuthorizationCode = db.AuthorizationCode;
const Token = db.Token;
initializePassport(passport);  // initializes local strategy

// OAuth2orize Server
const server = oauth2orize.createServer();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(flash());
app.use(helmet());
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
require('./config/passport-config')(passport); // Initialize local strategy

const CLIENT_ID = 1;
const CLIENT_SECRET = 'someSecretValue';
const REDIRECT_URI = 'https://localhost:3000/oauth/callback';
const STATE = 'someRandomStateValue'; // Optional, for CSRF




// Authorization endpoint
server.grant(
  oauth2orize.grant.code(async (client, redirectURI, user, ares, done) => {
    try {
    const code = randomBytes(32).toString('hex');

      await AuthorizationCode.create({
        code,
        clientID: client.clientID,
        redirectURI,
        userID: user.id,
      });
      done(null, code);
    } catch (err) {
      done(err);
    }
  })
);

// Exchange authorization code for access token
server.exchange(
  oauth2orize.exchange.code(async (client, code, redirectURI, done) => {
    try {
      const authCode = await AuthorizationCode.findOne({ where: { code } });

      if (!authCode || authCode.clientID !== client.clientID || authCode.redirectURI !== redirectURI) {
        return done(null, false); // Invalid request
      }

      // Generate access token
      const accessToken = Math.random().toString(36).substring(7);
      const token = await Token.create({
        token: accessToken,
        clientID: client.clientID,
        userID: authCode.userID,
      });

      // Cleanup authorization code
      await AuthorizationCode.destroy({ where: { code } });

      done(null, token.token);
    } catch (err) {
      done(err);
    }
  })
);


// Initialize OAuth2orize middleware
app.get('/authorize', ensureAuthenticated, server.authorization(async (clientID, redirectURI, done) => {
      try {
        const client = await Client.findOne({ where: { clientID } });

        if (client && client.redirectURI === redirectURI) {
          return done(null, client, redirectURI); // Valid client
        } else {
          return done(null, false); // Invalid client or redirect URI
        }
      } catch (err) {
        return done(err); // Handle unexpected errors
      }
    }),
    (req, res) => {
      const { response_type, state } = req.query;
  
      // Validate response_type
      if (response_type !== 'code') {
        return res.status(400).send('Invalid or missing response_type');
      }
  
      // Render the authorization page
      res.render('authorize', {
        transactionID: req.oauth2.transactionID,
        user: req.user,
        client: req.oauth2.client,
        state: state || '', // Include state parameter for CSRF protection if present
      });
    }
  );
  

app.post('/authorize', ensureAuthenticated, server.decision());

// Token endpoint
app.post('/token', passport.authenticate('basic', { session: false }), server.token(), server.errorHandler());

//Ensure user is authenticated
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

// Routes
app.get('/', (req, res) => res.render('welcome.ejs'));
app.get('/register', (req, res) => res.render('register.ejs'));
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  await User.create({ username, email, passwordHash: hashedPassword });
  res.redirect('/login');
});
app.get('/login', (req, res) => {
    const { client_id, redirect_uri, state } = req.query;
    console.log(client_id)

    if (!client_id || !redirect_uri) {
      return res.status(400).send('Invalid client_id or redirect_uri');
    }
  
    res.render('login.ejs', { client_id, redirect_uri, state });
});
app.post('/login', passport.authenticate('local', { failureRedirect: '/welcome', failureFlash: true }), (req, res) => {
    const { client_id, redirect_uri, state } = req.body;

    console.log('Query Params:', { client_id, redirect_uri, state });
  
    // Ensure all necessary parameters are present
    if (client_id && redirect_uri) {
      // Redirect to the authorize endpoint with response_type=code
      return res.redirect(`/authorize?client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}&response_type=code`);
    }
    // res.send("authorization failed");
});

// Sync database and start server
db.sequelize.sync({ force: false }).then(async () => {
    const existingClient = await Client.findOne({ where: { clientID: CLIENT_ID } });
    if (!existingClient) {
      // Add the static client to the database
      await Client.create({
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET, // Optional
        redirectURI: REDIRECT_URI,
        ownerID: 1,
      });
      console.log('Static client added to database');
    } else {
      console.log('Static client already exists');
    }
  app.listen(3001, () => console.log('Server running on http://localhost:3001'));
}).catch((err) => console.error('Error syncing models:', err));
