const checkAccessTokenValidity = require('../middleware/checkTokenValidity');
const { RefreshToken, AccessToken, AuthorizationCode, Client } = require('../models');
const crypto = require('crypto');

const fs = require('fs');

const jwt = require('jsonwebtoken');

/**
 *  Author: Madeline Moldrem
 *
 *  Handles the OAuth 2.0 token exchange and validation:
 *  - `getCallback`: Processes the OAuth callback, verifies the authorization code and state,
 *                   generates access and refresh tokens, stores them, and redirects to the dashboard.
 *  - `validate`: Validates the access token, checks its expiration, and issues a new token using
 *                the refresh token if necessary.
 *
 *  The `state` parameter:
 *  - Prevents CSRF attacks by ensuring the response is linked to the original request.
 *  - Stored in cookies and compared with the received query parameter before proceeding.
 */

const privateKey = fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH, 'utf8');

exports.getCallback = async (req, res) => {
    const { code, state: queryState } = req.query;
    const stateCookie = req.cookies.state;
    const { state }  = JSON.parse(stateCookie);
 
    // Validate the state parameter
    if (state !== queryState) { // will this work?
        return res.status(400).send('Invalid state parameter');
    }

    try {
        const authorizationCode = await findAuthorizationCode(code);
        if (!authorizationCode) { return res.status(400).json({ error: 'No auth code found in database' });
        } else if (authorizationCode.expires_at < Date.now()) { return res.status(400).json({ error: 'Expired auth code' });}


        /**
         *  Creating the JWT payload with the logged-in user's details (e.g., user_id and client_id).
         *  This allows downstream microservices to extract user information directly from the token,
         *  eliminating the need for extra database lookups.*
         */



        let role;
        let email;
        try {
            role = req.cookies['user_data'] ? JSON.parse(req.cookies['user_data']).role : null;
            email = req.cookies['user_data'] ? JSON.parse(req.cookies['user_data']).email: null;
        } catch (error) {
            console.error('Error parsing user_data cookie:', error);
            role = null;  // Fallback to null or a default role, like 'user'
            email = null;
        }
        
        // If role is required and is still null, you might want to handle that case explicitly
        if (!role || !email) {
            return res.status(400).json({ error: 'User role not found in cookie' });
        }
        
        const payload = {
            user_id: authorizationCode.user_id,
            client_id: authorizationCode.client_id,
            email: email,
            role: role,  // Now safely assigned
        };

        // access token
        const accessToken = jwt.sign(payload, privateKey, { algorithm: 'ES256', expiresIn: '1h' });
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
            secure: process.env.NODE_ENV === 'prod',  // Send over HTTPS in production
            sameSite: 'Strict',  // Prevent CSRF
            maxAge: 3600000,  // 1 hour expiration
        });

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,  
            secure: process.env.NODE_ENV === 'prod',
            sameSite: 'Strict', 
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days expiration
        });

        await AuthorizationCode.destroy({ where: { authorization_code: code } })

        // Retrieve the client record to access the landing_page field.
        const client = await Client.findOne({ where: { client_id: authorizationCode.client_id } });
        const finalLandingPage = client.landing_page || client.redirect_uri;

        // Redirect the user to the client’s landing page.
        res.redirect(finalLandingPage);
    } catch (error) {
        console.error('Error processing callback:', error);
        return res.status(500).json({ error: 'Internal server error in GET callback' });
    }
}

const findAuthorizationCode = async (code, attempts = 3, delay = 100) => {
    const result = await AuthorizationCode.findOne({ where: { authorization_code: code } });
    if (result) return result;
    if (attempts <= 1) return null;
    console.log('Authorization code not found, retrying...');
    await new Promise(resolve => setTimeout(resolve, delay));
    return findAuthorizationCode(code, attempts - 1, delay);
};

// exports.validate = async (req, res) => {
//     const { access_token } = req.body; 
//     const refresh_token = req.cookies.refresh_token;  

//     if (!access_token) {
//         return res.status(400).json({ error: 'Missing access token' });
//     }

//     try {
 
//         const storedToken = await AccessToken.findOne({
//             where: { access_token },
//             include: [
//                 { model: Client, as: 'client' },
//                 { model: User, as: 'user' },
//             ],
//         });

//         if (storedToken) {
//             if (storedToken.expires_at < Date.now()) {
//                 console.log('Access token expired. Attempting to refresh...');

//                 // Handle refresh token if available
//                 if (!refresh_token) {
//                     return res.status(400).json({ error: 'No refresh token provided. Could not refresh.' });
//                 }

//                 const storedRefreshToken = await RefreshToken.findOne({
//                     where: { refresh_token },
//                 });

//                 if (!storedRefreshToken) {
//                     return res.status(400).json({ error: 'Invalid refresh token provided. Could not refresh.' });
//                 }

//                 if (storedRefreshToken.expires_at < Date.now()) {
//                     return res.status(401).json({ error: 'Refresh token expired. Please log in again.' });
//                 }

//              
//                 const newAccessToken = crypto.randomBytes(32).toString('hex');
//                 const newAccessTokenExpiresAt = Date.now() + 60 * 60 * 1000;  // 1 hour

//                 // Save the new access token
//                 await AccessToken.create({
//                     access_token: newAccessToken,
//                     expires_at: newAccessTokenExpiresAt,
//                     user_id: storedRefreshToken.user_id,
//                     client_id: storedRefreshToken.client_id,
//                 });

//                 // Delete the old access token and clear the old cookie
//                 await storedToken.destroy();
//                 res.clearCookie('access_token');

//                 // Send the new access token as a cookie and in the response body
//                 res.cookie('access_token', newAccessToken, {
//                     httpOnly: true,
//                     secure: process.env.NODE_ENV === 'production',
//                     sameSite: 'Strict',
//                     maxAge: 3600000,  // 1 hour expiration
//                 });

//                 // Respond with user data and the new access token
//                 return res.status(200).json({
//                     status: 'valid',
//                     user: { id: storedRefreshToken.user.id, username: storedRefreshToken.user.username },
//                     new_access_token: newAccessToken,
//                 });
//             } else {
//                 console.log('Access token is valid');
//                 return res.status(200).json({
//                     status: 'valid',
//                     user: { id: storedToken.user.id, username: storedToken.user.username },
//                 });
//             }
//         } else {
//             return res.status(401).json({ error: 'Invalid access token', message: 'Token does not exist in the database' });
//         }
//     } catch (error) {
//         console.error('Error validating access token:', error);
//         return res.status(500).json({ error: 'Internal server error' });
//     }
// };

exports.validate = (req, res) => {
    const token = req.body.access_token;
  
  //  this is just temporary
  if (token === "valid-token") {
    return res.status(200).send({ message: 'Token is valid' });
  }
  console.log(token)

  res.status(401).send({ message: 'Invalid or expired token' });

};
