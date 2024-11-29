const express = require('express');
const bodyParser = require('body-parser');
const OAuth2Server = require('oauth2-server');
const Request = OAuth2Server.Request;
const Response = OAuth2Server.Response;

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const oauth = new OAuth2Server({
    model: require('./model2'), // Import OAuth 2.0 model
    accessTokenLifetime: 60 * 60, // 1 hour
    allowBearerTokensInQueryString: true,
});






// Middleware to handle OAuth token generation
app.post('/oauth/token', async (req, res) => {
    const request = new Request(req);
    const response = new Response(res);
    console.log('print!')

    try {
        const token = await oauth.token(request, response);
        res.json(token);
    } catch (err) {
        res.status(err.code || 500).json(err);
    }
});

// Middleware to protect routes
app.get('/secure', async (req, res) => {
    const request = new Request(req);
    const response = new Response(res);

    try {
        await oauth.authenticate(request, response);
        res.send('Secure data accessed!');
    } catch (err) {
        res.status(err.code || 500).json(err);
    }
});

// Start the server
app.listen(3000, () => {
    console.log('OAuth2 server running on http://localhost:3000');
});
