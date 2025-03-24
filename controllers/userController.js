const { RefreshToken, AccessToken, AuthorizationCode, Client, User } = require('../models');
const axios = require('axios');

exports.getDashboard = async (req, res) => {
    // const userDataCookie = req.cookies.user_data;
    const accessToken = req.cookies.access_token;
    const response = await axios.get('http://127.0.0.1:5000/header', {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        });
    console.log(response.data);
    
    res.redirect('http://127.0.0.1:5000/discover')
}

exports.getFeed = async (req, res) => {
    const userDataCookie = req.cookies.user_data;
    const { firstName } = JSON.parse(userDataCookie);
    res.render('feed', { greeting: firstName,});
}