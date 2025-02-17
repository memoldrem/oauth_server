const { User, Client, AuthorizationCode, UserClientConsent } = require('../models');
const crypto = require('crypto');

/**
 *  Author: Madeline Moldrem
 *
 *  Handles the OAuth 2.0 authorization process:
 *  - `getAuthorize`: Validates the client and displays the authorization page where the user can approve or deny access.
 *  - `postAuthorize`: Processes the user's decision. If approved, generates and stores an authorization code, then redirects the user to the client’s redirect URI.
 *
 *  The `state` parameter:
 *  - It is sent by the client as part of the authorization request.
 *  - It helps prevent CSRF attacks by ensuring the response is associated with the correct request.
 *  - It is returned unchanged in the redirect to the client.
 */

exports.getAuthorize = async (req, res) => {
    const { client_id, redirect_uri, state } = req.query;
    const client = await Client.findOne({ where: { client_id } });

    const userDataCookie = req.cookies.user_data;
    const { userId, firstName } = JSON.parse(userDataCookie);

    // Check if the logged-in user is the owner of the client
    if (!client || client.owner_id !== userId) {
        return res.status(400).send('Unauthorized client');
    }

    // Check for prior consent
    const consent = await UserClientConsent.findOne({
        where: { user_id: userId, client_id }
    });

    if (consent && consent.consent_granted) {
        // If consent already exists, generate an authorization code and redirect
        const authorizationCode = crypto.randomBytes(16).toString('hex');
        const expiresAt = Date.now() + 10 * 60 * 1000; // Expires in 10 minutes
        console.log("Consent exists. Saving authorization code to the database...");
        try {
            await AuthorizationCode.create({
                authorization_code: authorizationCode,
                expires_at: expiresAt,
                redirect_uri, // The redirect URI provided by the client
                client_id,
                user_id: userId,
                state: crypto.randomBytes(16).toString('hex') // Additional state for CSRF
            });
            console.log("Authorization code saved.");

            // Redirect to the callback endpoint with the code and original state
            const redirectUrl = `${redirect_uri}?code=${authorizationCode}&state=${state}`;
            return res.redirect(redirectUrl);
        } catch (error) {
            console.error('Error saving authorization code:', error);
            return res.status(500).send('Internal Server Error');
        }
    } else {
        // Otherwise, render the consent page so the user can approve or deny access
        res.render('authorize', { client_id, redirect_uri, state });

    }
};

exports.postAuthorize = async (req, res) => {
    const { client_id, redirect_uri, state, decision } = req.body;
    const userDataCookie = req.cookies.user_data;
    const { userId, firstName } = JSON.parse(userDataCookie);
    
    const user = await User.findOne({ where: { user_id: userId} }); // need this too!

    if (decision === 'approve') {

        // Store (or update) the consent for this user and client
        // Using upsert to create or update the record as needed
        await UserClientConsent.upsert({
            user_id: userId,
            client_id: client_id,
            consent_granted: true
        });
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
                state: crypto.randomBytes(16).toString('hex'), // i think this is just never used? let's follow up on that tho --- this is required for csrf check
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
};
