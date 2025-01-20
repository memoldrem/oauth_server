const { RefreshToken, AccessToken, AuthorizationCode, Client, User } = require('../models');

exports.getDashboard = async (req, res) => {
    const userDataCookie = req.cookies.user_data;
    const { firstName } = JSON.parse(userDataCookie);
    res.render('dashboard', { greeting: firstName,});
}