const { Client, RefreshToken, AccessToken } = require('../models');
const passport = require('passport');
const initializePassport = require('../config/passport-config');
initializePassport(passport); // Initialize passport strategies
const crypto = require('crypto');

exports.getLogin = (req, res) => {
    const csrfToken = crypto.randomBytes(16).toString('hex')
    req.session.csrfToken = csrfToken;
    res.render('login', { csrf_token: csrfToken,})
};

exports.postLogin = (req, res, next) => {
    const {csrf_token} = req.body;
    if (csrf_token !== req.session.csrfToken) {
        return res.status(400).send('Invalid CSRF token');
    }

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
                const userId = user.user_id
                const firstName = user.first_name
                res.cookie('user_data', JSON.stringify({ userId, firstName }), {
                    httpOnly: true, // Cannot be accessed by JavaScript
                    secure: process.env.NODE_ENV === 'production', // Only set secure cookies in production
                    maxAge: 86400000, // Cookie expires in 1 day
                    sameSite: 'Strict', // Prevent CSRF attacks
                });
                
                const client = await Client.findOne({
                    where: {
                      owner_id: user.user_id,
                      client_name: `d${user.user_id}`, // default name, this part is hardcoded but i think it would be anyways?
                    },
                  });
                if (!client) {
                    console.error('Client not found!');
                    return res.status(400).send('Invalid client configuration.');
                }


                const state = crypto.randomBytes(16).toString('hex'); 

                res.cookie('state', JSON.stringify({ state }), {
                    httpOnly: true, // Cannot be accessed by JavaScript
                    secure: process.env.NODE_ENV === 'production', // Only set secure cookies in production
                    maxAge: 86400000, // Cookie expires in 1 day
                    sameSite: 'Strict', // Prevent CSRF attacks
                });

                const redirectUrl = `/authorize?client_id=${client.client_id}&redirect_uri=${encodeURIComponent(client.redirect_uri)}&state=${state}`;
                console.log('Redirecting to:', redirectUrl);
                return res.redirect(redirectUrl); // Redirect on success
            } catch (dbError) {
                console.error('Database error:', dbError);
                return next(dbError);
            }
        });
    })(req, res, next);
}



exports.logout = async (req, res) => {
    try {
        const accessTokenId = req.cookies.access_token;
        const refreshTokenId = req.cookies.refresh_token;

        if (accessTokenId) {
            await AccessToken.destroy({ where: { access_token: accessTokenId } });
            console.log('Access token destroyed');
        }

        if (refreshTokenId) {
            await RefreshToken.destroy({ where: { refresh_token: refreshTokenId } });
            console.log('Refresh token destroyed');
        }
       
        res.clearCookie('user_data');
        res.clearCookie('state'); 
        res.clearCookie('access_token'); 
        res.clearCookie('refresh_token'); 

        
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).json({ error: 'Error during session destruction' });
            }

            // Redirect user to login page or a confirmation page
            res.redirect('/login'); // also add a little flag that user logged out
        });
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).json({ error: 'Internal server error during logout' });
    }
};
