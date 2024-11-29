const express = require('express');
const app = express();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const dotenv = require('dotenv');
const OAuth2Server = require('oauth2-server');
const bodyParser = require('body-parser');
const db = require('../models');
const initializePassport = require('../config/passport-config');
const oauthModel = require('../config/oauth-model'); 
const helmet = require('helmet'); // secures http headers

dotenv.config();

const User = db.User; 
const Client = db.Client;
const AuthorizationCode = db.AuthorizationCode;

const oauth = new OAuth2Server({ 
  model: oauthModel,  // as defined by ./config/oauth-model
  accessTokenLifetime: 3600,  // 1 hour
  refreshTokenLifetime: 1209600,  // 14 days
});

initializePassport(passport);  // initializes local strategy

// Middleware 
app.set('view engine', 'ejs');
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(flash());
app.use(helmet());
app.use(session({ // review this more!!
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 },  // Use secure cookies in prod
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static('public'));

app.get('/', (req, res) => {
  const client_id = 1;  // Your fixed client ID
  const redirect_uri = "https://your-client-app.com/callback";  // Your fixed redirect URI
  const state = Math.random().toString(36).substring(7);  // Generate a random state for CSRF protection

  // Create the login URL
  const loginUrl = `/login?client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}`;
  
  // Redirect to login page
  res.redirect(loginUrl);
});


// Registration 
app.get('/register', (req, res) => { 
  res.render('register.ejs');
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body; 

  try {
    const existingUser = await User.findOne({ where: { username } }); // search database
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' }); // we could redirect instead probably. havent decided
    }

    const hashedPassword = await bcrypt.hash(password, 10); // bcrpyt will do the hash work
    const newUser = await User.create({ username, email, passwordHash: hashedPassword }); // add if user DNE!!
    res.redirect('/'); // back to login page
  } catch (error) { 
    console.error(error); 
    res.redirect('/register'); // retry registration?
  }
});

// Login
app.get('/login', (req, res) => {
  const { client_id, redirect_uri, state } = req.query;
  // Render the login page, passing the client_id, redirect_uri, and state for use in the form
  res.render('login', { client_id, redirect_uri, state });
});

app.post('/login', passport.authenticate('local', {
  failureRedirect: '/login',
  failureFlash: true,
}), (req, res) => {
  // Check if OAuth parameters are in the query


  const { client_id, redirect_uri, state } = req.query;


  if (client_id && redirect_uri) {
    console.log("this is running!")
    // If the user is logged in and OAuth parameters are present, redirect to authorize
    return res.redirect(`/authorize?client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}`);
  }

  // Otherwise, continue to the dashboard
  res.redirect('/login');
});


// The authorize endpoint checks if the user is authenticated.
// If they are authenticated, an authorization code is issued.
// If not, they are redirected to the login page, which after successful login, 
// will send them back to the /authorize endpoint with the authorization code.


// authorize endpoint
app.get('/authorize', async (req, res) => {

  const { response_type, client_id, redirect_uri, state } = req.query;

  try {
    const client = await Client.findOne({ where: { clientID: client_id } });

    if (client.redirectURI !== redirect_uri) {
      return res.status(400).json({ error: 'Invalid redirect URI' });
    }

    // check response_type??

    //my thinking is that they would only get to this step if they were authenticated
    if (!req.isAuthenticated()) {
    
      return res.redirect(
        `/login?client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}`
      );
    }
   

    // const code = oauthModel.generateAuthorizationCode(req.user, client);
    const code = Math.random().toString(36).substring(7); 
    // await db.AuthorizationCode.create({
    //   code,
    //   userId: req.user.id,
    //   clientID: client.clientID,
    //   redirectUri,
    // });

    const redirectUrl = `${redirect_uri}?code=${code}${
      state ? `&state=${state}` : ''
    }`;
    console.log("made it here")
    // res.redirect('/dashboard');
    res.redirect(redirectUrl);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});


// OAuth2 Token Generation Endpoint (for issuing tokens)
// Exchanges the authorization code for access and refresh tokens.
app.post('/token', async (req, res, next) => {
  const { code, client_id, client_secret, redirect_uri } = req.body;

  try {
    // Fetch client from database
    const client = await Client.findOne({ where: { clientID: client_id } }); // await
    if (!client || client.clientSecret !== client_secret) {
      return res.status(400).json({ error: 'Invalid client credentials' });
    }

    // Verify that the authorization code exists and matches the client
    const authCode = await AuthorizationCode.findOne({ // await
      where: { code, clientID: client.clientID, redirectUri: redirect_uri },
    });

    if (!authCode) {
      return res.status(400).json({ error: 'Invalid or expired authorization code' });
    }

    // Generate an OAuth access token (and optionally a refresh token)
    const token = oauthModel.generateAccessToken(authCode.userId, client.clientID);

    // Respond with the token
    res.json({
      access_token: token.accessToken,
      token_type: 'bearer',
      expires_in: token.expiresIn,
      refresh_token: token.refreshToken,  // Optional
    });

    // Clean up: delete the authorization code after it's used
   AuthorizationCode.destroy({ where: { code } }); // await

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error during token exchange' });
  }
});


// middleware to verify tokens
const authenticateToken = async (req, res, next) => {
  const request = new OAuth2Server.Request(req); 
  const response = new OAuth2Server.Response(res);

  try {
    const token = await oauth.authenticate(request, response);
    req.user = token.user;
    next();
  } catch (err) {
    res.status(err.code || 401).json({ error: 'Unauthorized' });
  }
};



// Protected Dashboard Route
app.get('/dashboard', authenticateToken, (req, res) => {
  res.render('dashboard.ejs', { user: req.user });
});

// Sync database and start the server
db.sequelize.sync({ force: false }).then(() => {
  app.listen(3001, () => {
    console.log("Server running on http://localhost:3001");
  });
}).catch((err) => {
  console.error("Error syncing models:", err);
});


const createStaticClient = async () => {
  try {
    // Check if the client already exists (using clientID)
    const existingClient = await Client.findOne({
      where: { clientID: 1 }
    });

    if (!existingClient) {
      // If client doesn't exist, create it
      const newClient = await Client.create({
        clientID: 1,  // Fixed client ID
        clientSecret: 'client-secret',  // Fixed secret
        redirectURI: 'https://your-client-app.com/callback',  // Fixed redirect URI
        ownerID: 1  // Reference to the owner (user ID)
      });
      console.log('Client created:', newClient);
    } else {
      console.log('Client already exists.');
    }
  } catch (error) {
    console.error('Error creating client:', error);
  }
};

// Call the function on app startup
createStaticClient();