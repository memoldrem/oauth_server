const { User, Client, AuthorizationCode, RefreshToken, AccessToken } = require('../models');
const crypto = require('crypto');


exports.getAuthorize = async (req, res) => {
    const { client_id, redirect_uri, state } = req.query;
    const client = await Client.findOne({ where: { client_id } }); // is this additional querying necessary?

    const userDataCookie = req.cookies.user_data;
    const { userId, firstName } = JSON.parse(userDataCookie);

    if (!client || client.owner_id !== userId) { // 
        return res.status(400).send('Unauthorized client');
    }
    res.render('authorize', { client_id, redirect_uri, state });
}

exports.postAuthorize = async (req, res) => {
    const { client_id, redirect_uri, state, decision } = req.body;
    const userDataCookie = req.cookies.user_data;
    const { userId, firstName } = JSON.parse(userDataCookie);
    
    const user = await User.findOne({ where: { user_id: userId} }); // need this too!

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
                user_id: user.user_id,
                state: crypto.randomBytes(16).toString('hex'), // i think this is just never used? let's follow up on that tho
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
}