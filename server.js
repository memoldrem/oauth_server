const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const passport = require('passport');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
require('dotenv').config();

// Passport setup
const initializePassport = require('./config/passport-config');
initializePassport(passport);

// Middleware
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

app.use(passport.initialize());
app.use(passport.session());

// Sync database
const db = require('./models');
const { AuthorizationCode, Token, Client, User } = require('./models');

(async () => {
    try {
        await db.sequelize.sync({ alter: true });
        console.log('Database synced successfully!');
    } catch (error) {
        console.error('Error syncing database:', error);
    }
})();

// Routes
app.get('/', async (req, res) => {
    try {
        res.redirect('/login');
    } catch (err) {
        console.error('Error during authorization redirect:', err);
        res.status(500).send('Server Error');
    }
});

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    staticUser.username = username;
    staticUser.password = hashedPassword;
    res.redirect('/login');
});

app.get('/login', (req, res) => res.render('login'));

app.post('/login', async (req, res) => {
    const staticClient = await Client.findOne({ where: { client_id: 1 } });
    const client_id = staticClient.client_id;
    const redirect_uri = staticClient.redirect_uri;
    const state = crypto.randomBytes(16).toString('hex');

    const redirectUrl = `/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${state}`;
    req.session.state = state;
    return res.redirect(redirectUrl);
});

app.get('/authorize', async (req, res) => {
    const { client_id, redirect_uri, state } = req.query;

    const client = await Client.findOne({ where: { client_id } });
    

    // if (!client || !client.redirect_uris.includes(redirect_uri)) {
    //     return res.status(400).send('Unauthorized redirect_uri');
    // }
    res.render('authorize', { client_id, redirect_uri, state });
});

app.post('/authorize', async (req, res) => {
    const { client_id, redirect_uri, state, decision } = req.body;
    const staticUser = await User.findOne({ where: { user_id: 1 } });

    if (decision === 'approve') {
        const authorizationCode = crypto.randomBytes(16).toString('hex');
        const expiresAt = Date.now() + 10 * 60 * 1000;

        try {
            AuthorizationCode.create({
                authorization_code: authorizationCode,
                expires_at: expiresAt,
                redirect_uri,
                client_id,
                user_id: staticUser.user_id,
                state: 'some_state',
            });

            const redirectUrl = `${redirect_uri}?code=${authorizationCode}&state=${state}`;
            return res.redirect(redirectUrl);
        } catch (error) {
            console.error('Error saving authorization code:', error);
            return res.status(500).send('Internal Server Error');
        }
    } else {
        res.send('Request denied');
    }
});

app.get('/callback', async (req, res) => {
    console.log(req.query);
    const { code, state } = req.query;
    if (state !== req.session.state) {app.get('/callback', async (req, res) => {
        console.log(req.query);
        const { code, state } = req.query;
        if (state !== req.session.state) {
            return res.status(400).send('Invalid state parameter');
        }
        try {
            console.log(`Authorization code received: ${code}`);
            
            // Check if the AuthorizationCode model is defined and accessible
            if (!AuthorizationCode) {
                throw new Error('AuthorizationCode model is not defined');
            }
    
            const authorizationCode = await AuthorizationCode.findOne({
                where: { authorization_code: code },
            });
    
            console.log(`Authorization code found: ${authorizationCode}`);
    
            if (!authorizationCode) {
                return res.status(400).json({ error: 'No auth code found in database' });
            } else if (authorizationCode.expires_at < Date.now()) {
                return res.status(400).json({ error: 'Expired auth code' });
            }
    
            const accessToken = crypto.randomBytes(32).toString('hex');
            const expiresAt = Date.now() + 60 * 60 * 1000;
    
            await Token.create({
                access_token: accessToken,
                refresh_token: crypto.randomBytes(32).toString('hex'),
                expires_at: expiresAt,
                user_id: authorizationCode.user_id,
                client_id: authorizationCode.client_id,
            });
    
            console.log('Access token created!');
    
            const redirectUri = authorizationCode.redirect_uri;
            await AuthorizationCode.destroy({ where: { authorization_code: code } });
    
            res.redirect(`${redirectUri}?access_token=${accessToken}&state=${req.query.state}`);
        } catch (error) {
            console.error('Error processing callback:', error);
            return res.status(500).json({ error: 'Internal server error in GET callback' });
        }
    });
        return res.status(400).send('Invalid state parameter');
    }
    try {
        console.log(`Authorization code received: ${code}`);
        
        // Check if the AuthorizationCode model is defined and accessible
        if (!AuthorizationCode) {
            throw new Error('AuthorizationCode model is not defined');
        }

        const authorizationCode = await AuthorizationCode.findOne({
            where: { authorization_code: code },
        });

        console.log(`Authorization code found: ${authorizationCode}`);

        if (!authorizationCode) {
            return res.status(400).json({ error: 'No auth code found in database' });
        } else if (authorizationCode.expires_at < Date.now()) {
            return res.status(400).json({ error: 'Expired auth code' });
        }

        const accessToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + 60 * 60 * 1000;

        await Token.create({
            access_token: accessToken,
            refresh_token: crypto.randomBytes(32).toString('hex'),
            expires_at: expiresAt,
            user_id: authorizationCode.user_id,
            client_id: authorizationCode.client_id,
        });

        console.log('Access token created!');

        const redirectUri = authorizationCode.redirect_uri;
        console.log(code);
        await AuthorizationCode.destroy({ where: { authorization_code: code } });

        res.redirect(`/secure?access_token=${accessToken}&state=${req.query.state}`);
    } catch (error) {
        console.error('Error processing callback:', error);
        return res.status(500).json({ error: 'Internal server error in GET callback' });
    }
});

app.get('/secure', (req, res) => {
    const { access_token } = req.query;

    if (!access_token) {
        return res.status(400).json({ error: 'missing_access_token' });
    }

    try {
        const storedToken = Token.findOne({
            where: { access_token },
            include: [
                { model: Client, as: 'client' },  // Specify alias
                { model: User, as: 'user' },      
            ],
        });

        if (!storedToken || storedToken.expires_at < Date.now()) {
            return res.status(401).json({ error: 'invalid_token', message: 'Token is invalid or expired' });
        }

        const { client_id, redirect_uri, user_id } = storedToken;

        res.render('dashboard', {
            client_id,
            redirect_uri,
            grant_type: 'authorization_code',
            code: '1',
            user: storedToken.user,
        });
    } catch (error) {
        console.error('Error validating access token:', error);
        return res.status(500).json({ error: 'internal_server_error in GET secure' });
    }
});

// Middleware to ensure the user is authenticated
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.send('User not authenticated');
}

// Start the server
const port = 3001;
app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
});