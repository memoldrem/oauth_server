const express = require('express');
const bodyParser = require('body-parser');
const OAuth2Server = require('oauth2-server');
// const Request = OAuth2Server.Request;
// const Response = OAuth2Server.Response;
const session = require('express-session');
// const db = require('./model');
const crypto = require('crypto');
require('dotenv').config();
const passport = require('passport');
const bcrypt = require('bcrypt');
const axios = require('axios');
const initializePassport = require('./config/passport-config');
const { url } = require('inspector');


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


app.get('/', (req, res) => {res.render('welcome')});
app.post('/', (req, res) => {

    const clientId = '1';
    const redirectUri = staticClient.redirectUri;
    const state = 'xyz';
    res.redirect(`/login?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`);    
});
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
    console.log('1', req.query);


    if (!client_id || !redirect_uri) {
      return res.status(400).send('Invalid client_id or redirect_uri');
    }
   
  
    res.render('login.ejs', { client_id, redirect_uri, state });
});

// Post login.
app.post('/login', passport.authenticate('local', { failureRedirect: '/login' }), (req, res) => {
    
    const { client_id, redirect_uri, state } = req.body;

    //     if (!client_id || !redirect_uri) {
    //         return res.status(400).send('Invalid client_id or redirect_uri');
    //     }

    //     // Redirect to `/oauth/authorize` with query parameters
    //     const path = '/oauth/authorize';
    //     console.log("post login")
     
    //     const redirectUrl = `${path}?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}`;


    //     console.log('Redirecting to:', redirectUrl);
    //     return res.redirect(redirectUrl);

    console.log('1', req.body);

    if (!client_id || !redirect_uri) {
        return res.status(400).send('Invalid client_id or redirect_uri');
    }

    // Redirect to authorization page
    const redirectUrl = `/oauth/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${state}`;
    return res.redirect(redirectUrl);

});



app.get('/oauth/authorize', ensureAuthenticated, function(req, res) {

    // return res.render('authorize', {
    //   client_id: req.query.client_id,
    //   redirect_uri: req.query.redirect_uri,
    //   client_secret: 'your-client-secret',
    // });
    const { client_id, redirect_uri, state } = req.query;

    if (
        client_id !== staticClient.clientId ||
        redirect_uri !== staticClient.redirectUri
    ) {
        return res.status(400).send('Invalid client_id or redirect_uri');
    }

    res.render('authorize', { client_id, redirect_uri, state });
  });


app.post('/oauth/authorize', (req, res) => {
    // const { client_id, redirect_uri, state, decision } = req.body;

    // if (decision === 'approve') {
    //     // Generate an authorization code
    //     const authorizationCode = crypto.randomBytes(16).toString('hex');
    //     const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes expiry

    //     // Store the authorization code and associated data
    //     authorizationCodes[authorizationCode] = {
    //         client_id,
    //         redirect_uri,
    //         user_id: staticUser.id,
    //         expiresAt,
    //     };

    //     const redirectUrl = `${redirect_uri}?code=${authorizationCode}&state=${state}`;
    //     return res.redirect(redirectUrl);
    // } else {
    //     // Deny access
    //     const redirectUrl = `${redirect_uri}?error=access_denied&state=${state}`;
    //     return res.redirect(redirectUrl);
    // }
    const { client_id, redirect_uri, state, decision } = req.body;
  

    if (decision === 'approve') {
        const authorizationCode = crypto.randomBytes(16).toString('hex');
        const expiresAt = Date.now() + 10 * 60 * 1000; // Expires in 10 minutes

        authorizationCodes[authorizationCode] = {
            client_id,
            redirect_uri,
            user_id: staticUser.id,
            expiresAt,
        };

        const redirectUrl = `${redirect_uri}?code=${authorizationCode}&state=${state}`;
        return res.redirect(redirectUrl);
    } else {
 
        return res.redirect('/'); // we could probably make this better
    }
});


app.get('/callback', ensureAuthenticated, async (req, res) => {
    const { code, state } = req.query;  // Retrieve the authorization code and state


    if (!code) {
        return res.status(400).json({ error: 'missing_code' });
    }

    // Create the POST request body for token exchange
    const tokenRequestData = {
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: 'http://localhost:3001/callback',
     // The same redirect URI asyour-client-id in the initial request
        client_id: '1',
        client_secret: 'your-client-secret'
    };

    try {
        // Send the POST request to the /oauth/token endpoint
        const tokenResponse = await axios.post('http://localhost:3001/oauth/token', tokenRequestData, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        const { access_token, token_type, expires_in } = tokenResponse.data;

        // Optionally store the access token in the session or a secure place
        // For example, you might store it in a cookie or a session variable
        // res.json({
        //     message: 'Authorization successful!',
        //     access_token: access_token,
        //     token_type: token_type,
        //     expires_in: expires_in
        // });
        res.redirect(`http://localhost:3001/secure?access_token=${access_token}`);
        // res.redirect('/secure') // change?
    } catch (err) {
        console.error('Error exchanging authorization code for access token', err);
        res.status(500).json({ error: 'token_exchange_failed', message: err.message });
    }
});

// Middleware to handle OAuth token generation
app.post('/oauth/token', async (req, res) => {
    // const request = new Request(req);
    // const response = new Response(res);
    // console.log('Incoming token request:', req.body);
    // console.log('print!')

    // try {
    //     console.log('trying..')

    //     const token = await oauth.token(request, response);
    //     res.json(token);
    // } catch (err) {
    //     console.log('issuing token failed.')
    //     res.status(err.code || 500).json(err);
    // }
    const { code, client_id, client_secret, redirect_uri, grant_type } = req.body;

    if (grant_type !== 'authorization_code') {
        return res.status(400).json({ error: 'unsupported_grant_type' });
    }
    console.log(req.body)

    if (
        client_id !== staticClient.clientId ||
        client_secret !== staticClient.clientSecret ||
        redirect_uri !== staticClient.redirectUri
    ) {
        return res.status(400).json({ error: 'invalid_client' });
    }

    const authCode = authorizationCodes[code];
    if (!authCode || authCode.expiresAt < Date.now()) {
        return res.status(400).json({ error: 'invalid_grant' });
    }

    const accessToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 60 * 60 * 1000; // Expires in 1 hour

    accessTokens[accessToken] = {
        user_id: authCode.user_id,
        client_id: authCode.client_id,
        expiresAt,
    };

    delete authorizationCodes[code]; // Invalidate the authorization code

    res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
    });
});

// Middleware to protect routes
app.get('/secure', ensureAuthenticated, (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ')
        ? authHeader.split(' ')[1]
        : req.query.access_token; // Fallback for query parameter

    if (!token) {
        return res.status(401).json({ error: 'invalid_request', message: 'Missing token' });
    }

    const storedToken = accessTokens[token];

    if (!storedToken || storedToken.expiresAt < Date.now()) {
        return res.status(401).json({ error: 'invalid_token', message: 'Token is invalid or expired' });
    }

    // res.render('dashboard', { user_id: storedToken.user_id });
    res.render('dashboard')
});


function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.send('user not authenticated')
  }

authorizationCodes = {}
accessTokens = {}
// Static client
const staticClient = {
    clientId: '1',
    clientSecret: 'your-client-secret',
    redirectUri: 'http://localhost:3001/callback',
};

// Static user
const staticUser = {
    id: '1',
    username: 'l@l.com',
    password: 'l', // Plaintext for simplicity (avoid in production)
};

// // Temporary stores for tokens and codes
// const authorizationCodes = {}; // To store authorization codes
// const accessTokens = {};       // To store access tokens

app.listen(3001, () => console.log('Server running on http://localhost:3001'));
