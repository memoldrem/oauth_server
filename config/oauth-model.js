// config/oauth-model.js
const { User, OAuthToken } = require('../models'); // Sequelize models for User and Token

module.exports = {
  getAccessToken: async (accessToken) => {
    return await OAuthToken.findOne({ where: { accessToken } });
  },
  getAuthorizationCode: async (code) => {
    // Find the authorization code in the database
    return await OAuthToken.findOne({ where: { authorizationCode: code } });
  },
  saveAuthorizationCode: async (code, client, user) => {
    // Save the authorization code to the database
    return await OAuthToken.create({
      authorizationCode: code.authorizationCode,
      expiresAt: code.expiresAt,
      clientId: client.id,
      userId: user.id,
    });
  },
  saveToken: async (token, client, user) => {
    // Save the token to the database
    return await OAuthToken.create({
      accessToken: token.accessToken,
      accessTokenExpiresAt: token.accessTokenExpiresAt,
      refreshToken: token.refreshToken,
      refreshTokenExpiresAt: token.refreshTokenExpiresAt,
      clientId: client.id,
      userId: user.id,
    });
  },
  getUser: async (username, password) => {
    // Find and authenticate the user
    const user = await User.findOne({ where: { username } });
    return user && user.verifyPassword(password) ? user : null;
  },

  getClient: async (username, password) => {
    // Find and authenticate the user
    const user = await User.findOne({ where: { username } });
    return user && user.verifyPassword(password) ? user : null;
  },
};
