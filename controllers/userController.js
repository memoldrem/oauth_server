const { RefreshToken, AccessToken, AuthorizationCode, Client, User } = require('../models');

exports.getDashboard = async (req, res) => {
    const { access_token } = req.query;
    if (!access_token) {
        return res.status(400).json({ error: 'missing_access_token' });
    }

    try {
        const storedToken = await AccessToken.findOne({
            where: { access_token },
            include: [
                { model: Client, as: 'client' },  // Specify alias
                { model: User, as: 'user' },      
            ],
        });

        if (!storedToken || storedToken.expires_at < Date.now()) {
            return res.status(401).json({ error: 'invalid_token', message: 'Token is invalid or expired' });
        }
        const userDataCookie = req.cookies.user_data;
        const { userId, firstName } = JSON.parse(userDataCookie);

        res.render('dashboard', { greeting: firstName,});
    } catch (error) {
        console.error('Error validating access token:', error);
        return res.status(500).json({ error: 'internal_server_error in GET dashboard' });
    }
}