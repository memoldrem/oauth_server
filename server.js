const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const passport = require('passport');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

require('dotenv').config();

// The User is the resource owner
// The Client is the application or service trying to access user resources
// The Authorization Server manages user authentication and issues tokens
// The Resource Server holds user data and validates the access tokens for authorization



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
app.use(express.static('public')); // this is for CSS


app.use(passport.initialize());
app.use(passport.session());

// Sync database
const db = require('./models');
const { AuthorizationCode, Token, Client, User } = require('./models');

// Passport setup
const initializePassport = require('./config/passport-config');
initializePassport(passport); // Initialize passport strategies

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
    const { username, password, email} = req.body;
    // if(password.length < 8){

    // }

    try {
        const existingUser = await User.findOne({ where: { username } }); // Check if the username already exists
        if (existingUser) {
            return res.status(400).send('Username already exists');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({
            username,
            email,
            password_hash: hashedPassword,
          });
        // Insert the user into the database

        console.log(`User registered successfully: ${newUser.username}`);
        res.redirect('/login');
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user');
    }
});

app.get('/login', (req, res) => res.render('login'));

app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        console.log('Passport authenticate called'); // Debugging log
        if (err) {
            console.error('Authentication error:', err);
            return next(err);
        }
        if (!user) {
            console.log('Authentication failed:', info.message);
            return res.redirect('/login');
        }
        req.login(user, async (err) => {
            if (err) {
                console.error('Login error:', err);
                return next(err);
            }
            try {
                const client = await Client.findOne({ where: { client_id: 1 } }); // Hardcoded client
                if (!client) {
                    console.error('Client not found!');
                    return res.status(400).send('Invalid client configuration.');
                }
                const client_id = client.client_id;
                const redirect_uri = client.redirect_uri;
                const state = crypto.randomBytes(16).toString('hex');
                req.session.state = state;

                const redirectUrl = `/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${state}`;
                console.log('Redirecting to:', redirectUrl);
                return res.redirect(redirectUrl); // Redirect on success
            } catch (dbError) {
                console.error('Database error:', dbError);
                return next(dbError);
            }
            return res.redirect('/dashboard'); // Redirect after login
        });
    })(req, res, next);
});



app.get('/authorize', ensureAuthenticated, async (req, res) => {
    const { client_id, redirect_uri, state } = req.query;

    const client = await Client.findOne({ where: { client_id } });
    

    if (!client || !client.redirect_uris.includes(redirect_uri)) {
        return res.status(400).send('Unauthorized redirect_uri');
    }
    res.render('authorize', { client_id, redirect_uri, state });
});

app.post('/authorize', async (req, res) => {
    const { client_id, redirect_uri, state, decision } = req.body;
    const staticUser = await User.findOne({ where: { user_id: 1 } });

    if (decision === 'approve') {
        const authorizationCode = crypto.randomBytes(16).toString('hex');
        const expiresAt = Date.now() + 10 * 60 * 1000;
        console.log("Saving authorization code to the database...");
        try {
            AuthorizationCode.create({
                authorization_code: authorizationCode,
                expires_at: expiresAt,
                redirect_uri,
                client_id,
                user_id: staticUser.user_id,
                state: 'some_state',
            });
            console.log("Authorization code saved.");

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

app.get('/callback', ensureAuthenticated, async (req, res) => {
    console.log('Callback route triggered');
    console.log(req.query);
    const { code, state } = req.query;

    // Validate the state parameter
    if (state !== req.session.state) {
        return res.status(400).send('Invalid state parameter');
    }

    try {
        console.log(`Authorization code received: ${code}`);

        // Check if the AuthorizationCode model is defined and accessible
        if (!AuthorizationCode) {
            throw new Error('AuthorizationCode model is not defined');
        }

        console.log("Checking authorization code in database...");
        let authorizationCode;

        // Retry loop for fetching the authorization code
        for (let attempt = 0; attempt < 3; attempt++) {
            console.log("Attempt", attempt + 1);
            authorizationCode = await AuthorizationCode.findOne({
                where: { authorization_code: code },
            });

            if (authorizationCode) {
                console.log('Authorization code found:', authorizationCode);
                break;
            } else {
                console.log('Authorization code not found, retrying...');
                await new Promise(resolve => setTimeout(resolve, 100)); // wait 100ms
            }
        }

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

        // Redirect to the appropriate URL with the access token and state
        res.redirect(`secure?access_token=${accessToken}&state=${req.query.state}`); // should this come from database?

    } catch (error) {
        console.error('Error processing callback:', error);
        return res.status(500).json({ error: 'Internal server error in GET callback' });
    }
});


app.get('/secure', ensureAuthenticated, async (req, res) => {
    const { access_token } = req.query;

    if (!access_token) {
        return res.status(400).json({ error: 'missing_access_token' });
    }

    try {
        const storedToken = await Token.findOne({
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

app.delete('/logout', (req, res) => {
    req.logOut();
    res.redirect('/login');
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

