const checkAccessTokenValidity = require('../middleware/checkTokenValidity');
const { RefreshToken, AccessToken, AuthorizationCode } = require('../models');
const crypto = require('crypto');



exports.getCallback = async (req, res) => {
    const { code, state: queryState } = req.query;
    const stateCookie = req.cookies.state;
    const { state }  = JSON.parse(stateCookie);
 
    // Validate the state parameter
    if (state !== queryState) { // will this work?
        return res.status(400).send('Invalid state parameter');
    }

    try {
        let authorizationCode;
        for (let attempt = 0; attempt < 3; attempt++) { // needed this because timing kept messing up???
            authorizationCode = await AuthorizationCode.findOne({
                where: { authorization_code: code },
            });
            if (authorizationCode) { break; } else {
                console.log('Authorization code not found, retrying...');
                await new Promise(resolve => setTimeout(resolve, 100)); // wait 100ms
            }
        }

        if (!authorizationCode) { return res.status(400).json({ error: 'No auth code found in database' });
        } else if (authorizationCode.expires_at < Date.now()) { return res.status(400).json({ error: 'Expired auth code' });}

        // access token
        const accessToken = crypto.randomBytes(32).toString('hex');
        const accessTokenExpiresAt = Date.now() + 60 * 60 * 1000;  // Access token expires in 1 hour
  
          // refresh token
        const refreshToken = crypto.randomBytes(32).toString('hex');
        const refreshTokenExpiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000; // Refresh token expires in 30 days
  
        await AccessToken.create({
            access_token: accessToken,
            expires_at: accessTokenExpiresAt,
            user_id: authorizationCode.user_id,
            client_id: authorizationCode.client_id,
        });
        console.log('Access token created!');

        await RefreshToken.create({
            refresh_token: refreshToken,
            expires_at: refreshTokenExpiresAt,
            user_id: authorizationCode.user_id,
            client_id: authorizationCode.client_id,
        });
        console.log('Refresh token created!');

        res.cookie('access_token', accessToken, {
            httpOnly: true,  // Prevent JavaScript access
            secure: process.env.NODE_ENV === 'production',  // Send over HTTPS in production
            sameSite: 'Strict',  // Prevent CSRF
            maxAge: 3600000,  // 1 hour expiration
        });

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,  
            secure: process.env.NODE_ENV === 'production',  
            sameSite: 'Strict', 
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days expiration
        });

        await AuthorizationCode.destroy({ where: { authorization_code: code } })
        res.redirect('dashboard');
        // res.redirect(`dashboard?access_token=${accessToken}&state=${queryState}`); 
    } catch (error) {
        console.error('Error processing callback:', error);
        return res.status(500).json({ error: 'Internal server error in GET callback' });
    }
}

exports.validate = async (req, res) => {
    const { access_token } = req.body;  // Token sent from Flask server
    const refresh_token = req.cookies.refresh_token;  

    if (!access_token) {
        return res.status(400).json({ error: 'Missing access token' });
    }

    try {
 
        const storedToken = await AccessToken.findOne({
            where: { access_token },
            include: [
                { model: Client, as: 'client' },
                { model: User, as: 'user' },
            ],
        });

        if (storedToken) {
            if (storedToken.expires_at < Date.now()) {
                console.log('Access token expired. Attempting to refresh...');

                // Handle refresh token if available
                if (!refresh_token) {
                    return res.status(400).json({ error: 'No refresh token provided. Could not refresh.' });
                }

                const storedRefreshToken = await RefreshToken.findOne({
                    where: { refresh_token },
                });

                if (!storedRefreshToken) {
                    return res.status(400).json({ error: 'Invalid refresh token provided. Could not refresh.' });
                }

                if (storedRefreshToken.expires_at < Date.now()) {
                    return res.status(401).json({ error: 'Refresh token expired. Please log in again.' });
                }

                // Generate a new access token
                const newAccessToken = crypto.randomBytes(32).toString('hex');
                const newAccessTokenExpiresAt = Date.now() + 60 * 60 * 1000;  // 1 hour

                // Save the new access token
                await AccessToken.create({
                    access_token: newAccessToken,
                    expires_at: newAccessTokenExpiresAt,
                    user_id: storedRefreshToken.user_id,
                    client_id: storedRefreshToken.client_id,
                });

                // Delete the old access token and clear the old cookie
                await storedToken.destroy();
                res.clearCookie('access_token');

                // Send the new access token as a cookie and in the response body
                res.cookie('access_token', newAccessToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'Strict',
                    maxAge: 3600000,  // 1 hour expiration
                });

                // Respond with user data and the new access token
                return res.status(200).json({
                    status: 'valid',
                    user: { id: storedRefreshToken.user.id, username: storedRefreshToken.user.username },
                    new_access_token: newAccessToken,
                });
            } else {
                console.log('Access token is valid');
                return res.status(200).json({
                    status: 'valid',
                    user: { id: storedToken.user.id, username: storedToken.user.username },
                });
            }
        } else {
            return res.status(401).json({ error: 'Invalid access token', message: 'Token does not exist in the database' });
        }
    } catch (error) {
        console.error('Error validating access token:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};