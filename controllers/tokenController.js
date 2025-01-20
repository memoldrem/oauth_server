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

            // Set a cookie for access token
        res.cookie('access_token', accessToken, {
            httpOnly: true,  // Prevent JavaScript access
            secure: process.env.NODE_ENV === 'production',  // Send over HTTPS in production
            sameSite: 'Strict',  // Prevent CSRF
            maxAge: 3600000,  // 1 hour expiration
        });

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,  // Prevent JavaScript access
            secure: process.env.NODE_ENV === 'production',  // Send over HTTPS in production
            sameSite: 'Strict',  // Prevent CSRF
            maxAge: 30 * 24 * 60 * 60 * 1000,  // Refresh token expires in 30 days
        });

        await AuthorizationCode.destroy({ where: { authorization_code: code } });
        res.redirect(`dashboard?access_token=${accessToken}&state=${queryState}`); 
    } catch (error) {
        console.error('Error processing callback:', error);
        return res.status(500).json({ error: 'Internal server error in GET callback' });
    }
}

exports.postRefresh = async (req, res) => {
    const { refresh_token } = req.body;
    if (!refresh_token) { return res.status(400).json({ error: 'Missing refresh token' });}
    try {
        const refreshTokenRecord = await RefreshToken.findOne({where: { refresh_token }});

        if (!refreshTokenRecord) { return res.status(400).json({ error: 'Invalid refresh token' });}
        if (refreshTokenRecord.expires_at < Date.now()) {return res.status(400).json({ error: 'Expired refresh token' });}

        const newAccessToken = crypto.randomBytes(32).toString('hex');
        const newAccessTokenExpiresAt = Date.now() + 60 * 60 * 1000; // 1 hour

        await AccessToken.create({
            access_token: newAccessToken,
            expires_at: newAccessTokenExpiresAt,
            user_id: refreshTokenRecord.user_id,
            client_id: refreshTokenRecord.client_id
        });

        res.json({ access_token: newAccessToken });
    } catch (error) {
        console.error('Error refreshing access token:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}