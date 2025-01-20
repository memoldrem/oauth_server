const { AccessToken, RefreshToken, User, Client } = require('../models');
const crypto = require('crypto');

const checkAccessTokenValidity = async (req, res, next) => {
    const refresh_token = req.cookies.refresh_token;
    if (!req.cookies.access_token) {
        return res.status(400).json({ error: 'Missing access token' });
    }

    try {

        const storedToken = await AccessToken.findOne({
            where: { access_token: req.cookies.access_token },
            include: [
                { model: Client, as: 'client' },
                { model: User, as: 'user' },
            ],
        });

        if (storedToken) {
            if (storedToken.expires_at < Date.now()) {
                console.log('Access token expired. Attempting to refresh...');
                
                if (!refresh_token) {
                    return res.status(400).json({ error: 'No refresh token provided. Could not refresh.' });
                }

                // Find the refresh token in the database
                const storedRefreshToken = await RefreshToken.findOne({
                    where: { refresh_token },
                });

                if (!storedRefreshToken) {
                    return res.status(400).json({ error: 'Invalid refresh token provided. Could not refresh.' });
                }

               
                if (storedRefreshToken.expires_at < Date.now()) {
                    res.redirect('/logout'); // LOG OUT the user and include a message about how the session timed out
                }
                
                // Generate a new access token
                const newAccessToken = crypto.randomBytes(32).toString('hex');
                const newAccessTokenExpiresAt = Date.now() + 60 * 60 * 1000;  // 1 hour

                // Update or create new access token
                await AccessToken.create({
                    access_token: newAccessToken,
                    expires_at: newAccessTokenExpiresAt,
                    user_id: storedRefreshToken.user_id,
                    client_id: storedRefreshToken.client_id,
                });

                await storedToken.destroy(); // Delete the old access token
                res.clearCookie('access_token'); 

                res.cookie('access_token', newAccessToken, {
                    httpOnly: true,  // Prevent JavaScript access
                    secure: process.env.NODE_ENV === 'production',  // Send over HTTPS in production
                    sameSite: 'Strict',  // Prevent CSRF
                    maxAge: 3600000,  // 1 hour expiration
                });

                // Return new access token to the user
                return next();

            } else {
                console.log('Access token is valid');
                req.user = storedToken.user;
                req.client = storedToken.client;
                return next();
            }
        } else {
            return res.status(401).json({ error: 'Invalid access token', message: 'Token does not exist in the database' });
        }

    } catch (error) {
        console.error('Error validating access token:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};

module.exports = checkAccessTokenValidity;
