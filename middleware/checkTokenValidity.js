const { AccessToken, RefreshToken, User, Client } = require('../models');
const crypto = require('crypto');

const fs = require('fs');

/**
 *  Author: Madeline Moldrem
 *
 *  Middleware for validating and refreshing OAuth 2.0 access tokens:
 *  - Checks if the request contains a valid access token.
 *  - If the token is valid and not expired, attaches the authenticated user and client to the request.
 *  - If the token is expired and a valid refresh token is present, issues a new access token.
 *  - If both tokens are invalid or expired, logs the user out and requires re-authentication.
 *
 *  Security Considerations:
 *  - Uses `httpOnly` and `secure` cookies to prevent token theft via JavaScript.
 *  - Enforces strict expiration rules for access and refresh tokens.
 */


const publicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH, 'utf8');

const checkAccessTokenValidity = async (req, res, next) => {
    const refresh_token = req.cookies.refresh_token;
    const token = req.cookies.access_token;

    if (!token) {
        return res.status(400).json({ error: 'Missing access token' });
    }

    // Verify the JWT access token
    jwt.verify(token,  publicKey, { algorithms: ['ES256'] }, async (err, decoded) => {
        if (err) {
            // If the token expired, attempt to refresh it
            if (err.name === 'TokenExpiredError') {
                console.log('Access token expired. Attempting to refresh...');

                if (!refresh_token) {
                    return res.status(400).json({ error: 'No refresh token provided. Could not refresh.' });
                }

                // Look up the refresh token in your database
                const storedRefreshToken = await RefreshToken.findOne({
                    where: { refresh_token },
                });

                if (!storedRefreshToken) {
                    return res.status(400).json({ error: 'Invalid refresh token provided. Could not refresh.' });
                }

                if (storedRefreshToken.expires_at < Date.now()) {
                    // Token expired—log out the user (or handle as needed)
                    return res.redirect('/logout');
                }

                // Create a new JWT access token using the refresh token's details
                const newPayload = {
                    user_id: storedRefreshToken.user_id,
                    client_id: storedRefreshToken.client_id,
                };
                const newAccessToken = jwt.sign(newPayload, process.env.JWT_SECRET, { expiresIn: '1h' });
                const newAccessTokenExpiresAt = Date.now() + 60 * 60 * 1000; // 1 hour

                // Optionally, store the new token in your database (for revocation purposes)
                await AccessToken.create({
                    access_token: newAccessToken,
                    expires_at: newAccessTokenExpiresAt,
                    user_id: storedRefreshToken.user_id,
                    client_id: storedRefreshToken.client_id,
                });

                // Remove the old access token record if needed and clear the cookie
                // (Assuming you want to delete the expired token from your database)
                await AccessToken.destroy({ where: { access_token: token } });
                res.clearCookie('access_token');

                // Set the new access token as an HTTP-only cookie
                res.cookie('access_token', newAccessToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'prod',
                    sameSite: 'Strict',
                    maxAge: 3600000, // 1 hour
                });
``
                // Attach the new payload to the request
                req.user = newPayload;
                return next();
            } else {
                // For other errors, return an unauthorized response
                return res.status(401).json({ error: 'Invalid or expired token' });
            }
        } else {
            // Token is valid—attach the decoded payload to the request (e.g., user_id, client_id)
            req.user = decoded;
            return next();
        }
    });
};

module.exports = checkAccessTokenValidity;
