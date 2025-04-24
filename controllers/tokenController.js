const fs = require('fs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { RefreshToken, AccessToken, AuthorizationCode, Client, User } = require('../models');

// Load keys for JWT
const privateKey = fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH, 'utf8');
const publicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH, 'utf8');

exports.getCallback = async (req, res) => {
    const { code, state: queryState } = req.query;
    const stateCookie = req.cookies.state;

    const { state } = JSON.parse(stateCookie);

    if (state !== queryState) {
        return res.status(400).send('Invalid state parameter');
    }

    try {
        let authorizationCode;
        for (let attempt = 0; attempt < 3; attempt++) {
            authorizationCode = await AuthorizationCode.findOne({
                where: { authorization_code: code },
            });
            if (authorizationCode) break;
            console.log('Authorization code not found, retrying...');
            await new Promise(resolve => setTimeout(resolve, 100)); // Wait 100ms
        }

        if (!authorizationCode) {
            return res.status(400).json({ error: 'No auth code found in database' });
        }

        if (authorizationCode.expires_at < Date.now()) {
            return res.status(400).json({ error: 'Expired auth code' });
        }

        // Create access token
        const payload = {
            user_id: authorizationCode.user_id,
            client_id: authorizationCode.client_id,
        };

        const accessToken = jwt.sign(payload, privateKey, {
            algorithm: 'RS256',
            expiresIn: '1h',
        });

        const accessTokenExpiresAt = Date.now() + 60 * 60 * 1000;

        // Create refresh token
        const refreshToken = crypto.randomBytes(32).toString('hex');
        const refreshTokenExpiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;

        await AccessToken.create({
            access_token: accessToken,
            expires_at: accessTokenExpiresAt,
            user_id: authorizationCode.user_id,
            client_id: authorizationCode.client_id,
        });

        await RefreshToken.create({
            refresh_token: refreshToken,
            expires_at: refreshTokenExpiresAt,
            user_id: authorizationCode.user_id,
            client_id: authorizationCode.client_id,
        });

        res.cookie('access_token', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'prod',
            sameSite: 'Strict',
            maxAge: 3600000,
        });

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'prod',
            sameSite: 'Strict',
            maxAge: 30 * 24 * 60 * 60 * 1000,
        });

        await AuthorizationCode.destroy({ where: { authorization_code: code } });

        res.redirect('dashboard');
    } catch (error) {
        console.error('Error processing callback:', error);
        return res.status(500).json({ error: 'Internal server error in GET callback' });
    }
};

exports.validate = async (req, res, next) => {
    const token = req.cookies.access_token;
    const refresh_token = req.cookies.refresh_token;

    if (!token) {
        return res.status(400).json({ error: 'Missing access token' });
    }

    jwt.verify(token, publicKey, { algorithms: ['RS256'] }, async (err, decoded) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                console.log('Access token expired. Attempting to refresh...');

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
                    return res.redirect('/logout');
                }

                const newPayload = {
                    user_id: storedRefreshToken.user_id,
                    client_id: storedRefreshToken.client_id,
                };

                const newAccessToken = jwt.sign(newPayload, privateKey, {
                    algorithm: 'RS256',
                    expiresIn: '1h',
                });

                const newAccessTokenExpiresAt = Date.now() + 60 * 60 * 1000;

                await AccessToken.create({
                    access_token: newAccessToken,
                    expires_at: newAccessTokenExpiresAt,
                    user_id: storedRefreshToken.user_id,
                    client_id: storedRefreshToken.client_id,
                });

                await AccessToken.destroy({ where: { access_token: token } });
                res.clearCookie('access_token');

                res.cookie('access_token', newAccessToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'prod',
                    sameSite: 'Strict',
                    maxAge: 3600000,
                });

                req.user = newPayload;
                return next();
            } else {
                return res.status(401).json({ error: 'Invalid or expired token' });
            }
        } else {
            req.user = decoded;
            return next();
        }
    });
};
