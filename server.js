const express = require('express');
const bodyParser = require('body-parser');
const OAuth2Server = require('oauth2-server');
const Request = OAuth2Server.Request;
const Response = OAuth2Server.Response;
const session = require('express-session');
const db = require('./model');
const crypto = require('crypto');
const OauthClient = db.OauthClient;
require('dotenv').config();
const passport = require('passport');
const initializePassport = require('./config/passport-config');


const app = express();
initializePassport(passport); 
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');

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


require('./config/passport-config')(passport);

const oauth = new OAuth2Server({
    model: require('./model2'), // Import OAuth 2.0 model
    accessTokenLifetime: 60 * 60, // 1 hour
    allowBearerTokensInQueryString: true,
});


app.get('/', (req, res) => res.render('welcome'));
app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, email, passwordHash: hashedPassword });
    res.redirect('/login');
  });

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



app.get('/oauth/authorize', ensureAuthenticated, function(req, res) {

    return res.render('authorize', {
      client_id: req.query.client_id,
      redirect_uri: req.query.redirect_uri,
      client_secret: 'your-client-secret',
    });
  });


app.post('/oauth/authorize', ensureAuthenticated, (req, res) => {
    const { client_id, redirect_uri, state, decision } = req.body;

    if (decision === 'approve') {
        // Generate an authorization code
        const authorizationCode = crypto.randomBytes(16).toString('hex');
        const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes expiry

        // Store the authorization code and associated data
        authorizationCodes[authorizationCode] = {
            client_id,
            redirect_uri,
            user_id: staticUser.id,
            expiresAt,
        };

        const redirectUrl = `${redirect_uri}?code=${authorizationCode}&state=${state}`;
        return res.redirect(redirectUrl);
    } else {
        // Deny access
        const redirectUrl = `${redirect_uri}?error=access_denied&state=${state}`;
        return res.redirect(redirectUrl);
    }
});

// Middleware to handle OAuth token generation
app.post('/oauth/token', async (req, res) => {
    const request = new Request(req);
    const response = new Response(res);
    console.log('Incoming token request:', req.body);
    console.log('print!')

    try {
        console.log('trying..')

        const token = await oauth.token(request, response);
        res.json(token);
    } catch (err) {
        console.log('issuing token failed.')
        res.status(err.code || 500).json(err);
    }
});

// Middleware to protect routes
app.get('/secure', async (req, res) => {
    const request = new Request(req);
    const response = new Response(res);

    try {
        await oauth.authenticate(request, response);
        res.send('Secure data accessed!');
    } catch (err) {
        res.status(err.code || 500).json(err);
    }
});

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.send('user not authenticated')
  }

// // Start listening for requests.
// db.sequelize.sync({ force: false }).then(async () => {
//     const existingClient = await OauthClient.findOne({ where: { clientId: '1' } });
//     if (!existingClient) {
//       // Add the static client to the database
//       await OauthClient.create({
//         clientId: '1',
//         clientSecret: 'your-client-secret',
//         redirectUri: 'http://your-redirect-uri.com',
//       });
//       console.log('Static client added to database');
//     } else {
//       console.log('Static client already exists');
//     }
  
//     app.listen(3001, () => console.log('Server running on http://localhost:3001'));
//   }).catch((err) => console.error('Error syncing models:', err));

// Static client
const staticClient = {
    clientId: '1',
    clientSecret: 'your-client-secret',
    redirectUri: 'http://your-redirect-uri.com',
};

// Static user
const staticUser = {
    id: '123',
    username: 'testuser',
    password: 'password', // Plaintext for simplicity (avoid in production)
};

// // Temporary stores for tokens and codes
// const authorizationCodes = {}; // To store authorization codes
// const accessTokens = {};       // To store access tokens

