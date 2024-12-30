const express = require('express');
const session = require('express-session');
const OAuth2Server = require('oauth2-server');
const bodyParser = require('body-parser');
const passport = require('passport');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
require('dotenv').config();

//// Authorization Code Grant Flow ******
// 1. When the user logs in and authorizes a client, an authorization code is created in the AuthorizationCodes table 
// with an expiry timestamp and the user and client IDs.
// 2. When the client sends the authorization code to the /callback endpoint, 
// the server looks up the code in the AuthorizationCodes table, checks if it's 
// valid, and then issues an access token, which is stored in the AccessTokens table.
// 3. The access token expires (based on expires_at), and if needed, a refresh token can be 
// issued to get a new access token.


//Passport stuff
const initializePassport = require('./config/passport-config');
initializePassport(passport);

// middleware
const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }, // Update secure: true for production
    })
);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use((req, res, next) => { // Redirect HTTP traffic to HTTPS
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(`https://${req.hostname}${req.url}`);
    }
    next();
  });
  

app.use(passport.initialize());
app.use(passport.session());

// Sync database
const User = require('./models/User');
const Client = require('./models/Client');
const Token = require('./models/Token');
const db = require('./models');

(async () => {
    try {
        await db.sequelize.sync({ alter: true });
        console.log('Database synced successfully!');
    } catch (error) {
        console.error('Error syncing database:', error);
    }
})();


// In-memory storage for authorization codes and access tokens
const authorizationCodes = {};
const accessTokens = {};

// Simulated user database
const staticUser = {
    id: '1',
    username: 'l@l.com',
    password: 'l', // Plaintext for simplicity
};

// Simulated client details
const staticClient = {
    clientId: '1',
    clientSecret: 'your-client-secret',
    redirectUri: 'http://localhost:3001/callback',
};

// OAuth2 server configuration
const oauth = new OAuth2Server({
    model: require('./model2'), // Import OAuth 2.0 model
    accessTokenLifetime: 60 * 60, // 1 hour
    allowBearerTokensInQueryString: true,
});

// Routes

app.get('/', (req, res) => {
    const clientId = '1'; // hard coding, will change
    const redirectUri = staticClient.redirectUri;
    const state = 'xyz';
    res.redirect(`/login?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`);
});

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    staticUser.username = username;
    staticUser.password = hashedPassword;
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    const { client_id, redirect_uri, state } = req.query;
    console.log(req.query);

    if (!client_id || !redirect_uri) {
        return res.status(400).send('GET: Invalid client_id or redirect_uri');
    }

    res.render('login', {
        client_id,
        redirect_uri,
        state,
        client_secret: staticClient.clientSecret 
    });
});

// passport.authenticate('local', { failureRedirect: '/login' }),

app.post('/login',  (req, res) => {
    const { client_id, redirect_uri, state } = req.body;
    const redirectUrl = `/oauth/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${state}`;
    return res.redirect(redirectUrl);
});

// ensureAuthenticated,
// Authorization code flow
app.get('/oauth/authorize', (req, res) => {
    const { client_id, redirect_uri, state } = req.query;

    if (client_id !== staticClient.clientId || redirect_uri !== staticClient.redirectUri) {
        return res.status(400).send('Invalid client_id or redirect_uri');
    }

    res.render('authorize', { client_id, redirect_uri, state });
});

app.post('/oauth/authorize', (req, res) => {
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
        return res.redirect('/');
    }
});

// ensureAuthenticated, 

app.get('/callback', async (req, res) => {
    const { code } = req.query;

    if (!code) {
        return res.status(400).json({ error: 'missing_code' });
    }

    const authorizationCode = authorizationCodes[code];
    if (!authorizationCode || authorizationCode.expiresAt < Date.now()) {
        return res.status(400).json({ error: 'invalid_grant' });
    }

    const accessToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 60 * 60 * 1000; // Expires in 1 hour

    accessTokens[accessToken] = {
        user_id: authorizationCode.user_id,
        client_id: authorizationCode.client_id,
        expiresAt,
    };

    delete authorizationCodes[code]; // Invalidate the authorization code

    res.redirect(`http://localhost:3001/secure?access_token=${accessToken}&client_id=${authorizationCode.client_id}&redirect_uri=${authorizationCode.redirect_uri}`);
});

// ensureAuthenticated, 
app.get('/secure', (req, res) => {
    const { access_token } = req.query;
    const storedToken = accessTokens[access_token];

    if (!storedToken || storedToken.expiresAt < Date.now()) {
        return res.status(401).json({ error: 'invalid_token', message: 'Token is invalid or expired' });
    }

    const client_id = req.query.client_id; // Or fetch from elsewhere
    const redirect_uri = req.query.redirect_uri; // Or fetch from elsewhere
    const grant_type = 'authorization_code'; // This is fixed as per your example
    const code = '1'; // Example, replace with real value as needed

    // Render the dashboard and pass the values
    res.render('dashboard', { 
        client_id, 
        redirect_uri, 
        grant_type, 
        code 
    });

    if (!storedToken || storedToken.expiresAt < Date.now()) {
        return res.status(401).json({ error: 'invalid_token', message: 'Token is invalid or expired' });
    }

    res.render('dashboard');
});

// Middleware to ensure the user is authenticated
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.send('User not authenticated');
}

// Start server
app.listen(3001, () => console.log('Server running on http://localhost:3001'));
