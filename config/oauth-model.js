const { User, OAuthToken } = require('../models'); // Sequelize models for User and Token

module.exports = {
  // Retrieve a client based on client ID and secret
  getClient: async (clientId, clientSecret) => {
    const client = await db.Client.findOne({ where: { clientId } });
    if (!client) return null;
  
    // If client_secret is not needed, you can skip this check
    if (clientSecret && client.clientSecret !== clientSecret) {
      return null;
    }
  
    return {
      id: client.clientId,
      grants: client.grants, // e.g., ['authorization_code', 'refresh_token']
      redirectUris: [client.redirectUri],
    };
  },
  
  
  saveToken: async (token, client, user) => {
    try {
      const savedToken = await db.Token.create({
        accessToken: token.accessToken,
        accessTokenExpiresAt: token.accessTokenExpiresAt,
        refreshToken: token.refreshToken,
        refreshTokenExpiresAt: token.refreshTokenExpiresAt,
        clientId: client.id,
        userId: user.id,
      });

      return {
        accessToken: savedToken.accessToken,
        accessTokenExpiresAt: savedToken.accessTokenExpiresAt,
        refreshToken: savedToken.refreshToken,
        refreshTokenExpiresAt: savedToken.refreshTokenExpiresAt,
        client: { id: client.id },
        user: { id: user.id },
      };
    } catch (err) {
      console.error('Error in saveToken:', err);
      throw err;
    }
  },

  /**
   * Get access token details.
   */
  getAccessToken: async (accessToken) => {
    try {
      const token = await db.Token.findOne({
        where: { accessToken },
        include: [db.User, db.Client],
      });

      if (!token) return null;

      return {
        accessToken: token.accessToken,
        accessTokenExpiresAt: token.accessTokenExpiresAt,
        user: token.User,
        client: token.Client,
      };
    } catch (err) {
      console.error('Error in getAccessToken:', err);
      throw err;
    }
  },

  /**
   * Get the refresh token details.
   */
  getRefreshToken: async (refreshToken) => {
    try {
      const token = await db.Token.findOne({
        where: { refreshToken },
        include: [db.User, db.Client],
      });

      if (!token) return null;

      return {
        refreshToken: token.refreshToken,
        refreshTokenExpiresAt: token.refreshTokenExpiresAt,
        user: token.User,
        client: token.Client,
      };
    } catch (err) {
      console.error('Error in getRefreshToken:', err);
      throw err;
    }
  },

  /**
   * Revoke a refresh token (e.g., when a user logs out).
   */
  revokeToken: async (token) => {
    try {
      const deleted = await db.Token.destroy({
        where: { refreshToken: token.refreshToken },
      });

      return deleted > 0;
    } catch (err) {
      console.error('Error in revokeToken:', err);
      throw err;
    }
  },

  /**
   * Validate the user credentials for the password grant type.
   */
  getUser: async (username, password) => {
    try {
      const user = await db.User.findOne({ where: { username } });

      if (!user) return null;

      const validPassword = await bcrypt.compare(password, user.passwordHash);
      return validPassword ? user : null;
    } catch (err) {
      console.error('Error in getUser:', err);
      throw err;
    }
  },

  /**
   * Validate the authorization code.
   */
  getAuthorizationCode: async (code) => {
    try {
      const authCode = await db.AuthorizationCode.findOne({
        where: { code },
        include: [db.Client, db.User],
      });

      if (!authCode) return null;

      return {
        code: authCode.code,
        expiresAt: authCode.expiresAt,
        redirectUri: authCode.redirectUri,
        client: authCode.Client,
        user: authCode.User,
      };
    } catch (err) {
      console.error('Error in getAuthorizationCode:', err);
      throw err;
    }
  },

  /**
   * Save the authorization code.
   */
  saveAuthorizationCode: async (code, client, user) => {
    try {
      const authCode = await db.AuthorizationCode.create({
        code: code.authorizationCode,
        expiresAt: code.expiresAt,
        redirectUri: code.redirectUri,
        clientId: client.id,
        userId: user.id,
      });

      return {
        authorizationCode: authCode.code,
        expiresAt: authCode.expiresAt,
        redirectUri: authCode.redirectUri,
        client: { id: client.id },
        user: { id: user.id },
      };
    } catch (err) {
      console.error('Error in saveAuthorizationCode:', err);
      throw err;
    }
  },

  /**
   * Revoke an authorization code.
   */
  revokeAuthorizationCode: async (code) => {
    try {
      const deleted = await db.AuthorizationCode.destroy({
        where: { code: code.authorizationCode },
      });

      return deleted > 0;
    } catch (err) {
      console.error('Error in revokeAuthorizationCode:', err);
      throw err;
    }
  },

  /**
   * Verify the allowed grant types for a client.
   */
  verifyScope: async (token, scope) => {
    // Add custom scope validation logic here if needed
    return true;
  },

};

