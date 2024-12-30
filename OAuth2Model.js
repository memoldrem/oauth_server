const { Token, AuthorizationCode, Client, User } = require('./models'); // Import your models

module.exports = {
  getAccessToken: async (accessToken) => {
    const token = await Token.findOne({
      where: { access_token: accessToken },
      include: [
        { model: User, as: 'user' },
        { model: Client, as: 'client' }
      ]
    });
    if (!token) return null;
    return {
      accessToken: token.access_token,
      accessTokenExpiresAt: token.expires_at,
      client: token.client,
      user: token.user
    };
  },

  getClient: async (clientId, clientSecret) => {
    const client = await Client.findOne({ where: { client_id: clientId } });
    if (!client || client.client_secret !== clientSecret) return null;
    return {
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUris: [client.redirect_uri]
    };
  },

  saveAuthorizationCode: async (authorizationCode, client, user) => {
    const code = await AuthorizationCode.create({
      authorization_code: authorizationCode.authorizationCode,
      expires_at: authorizationCode.expiresAt,
      redirect_uri: authorizationCode.redirectUri,
      client_id: client.clientId,
      user_id: user.id
    });
    return {
      authorizationCode: code.authorization_code,
      expiresAt: code.expires_at,
      redirectUri: code.redirect_uri,
      client: { id: client.clientId },
      user: { id: user.id }
    };
  },

  getAuthorizationCode: async (authorizationCode) => {
    const code = await AuthorizationCode.findOne({
      where: { authorization_code: authorizationCode },
      include: [{ model: User, as: 'user' }, { model: Client, as: 'client' }]
    });
    if (!code) return null;
    return {
      authorizationCode: code.authorization_code,
      expiresAt: code.expires_at,
      redirectUri: code.redirect_uri,
      client: { id: code.client_id },
      user: { id: code.user_id }
    };
  },

  saveToken: async (token, client, user) => {
    const newToken = await Token.create({
      access_token: token.accessToken,
      refresh_token: token.refreshToken,
      expires_at: token.accessTokenExpiresAt,
      user_id: user.id,
      client_id: client.clientId
    });
    return {
      accessToken: newToken.access_token,
      refreshToken: newToken.refresh_token,
      accessTokenExpiresAt: newToken.expires_at,
      client: { id: newToken.client_id },
      user: { id: newToken.user_id }
    };
  },

  getRefreshToken: async (refreshToken) => {
    const token = await Token.findOne({
      where: { refresh_token: refreshToken },
      include: [{ model: User, as: 'user' }, { model: Client, as: 'client' }]
    });
    if (!token) return null;
    return {
      refreshToken: token.refresh_token,
      accessToken: token.access_token,
      accessTokenExpiresAt: token.expires_at,
      client: token.client,
      user: token.user
    };
  },

  revokeToken: async (token) => {
    await Token.destroy({ where: { access_token: token.accessToken } });
    return true;
  },

};
