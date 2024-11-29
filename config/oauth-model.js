const { OauthToken, OauthClient, User } = require('../old_news/model');

/**
 * Get access token.
 */
module.exports.getAccessToken = async function (bearerToken) {
  const token = await OauthToken.findOne({ where: { accessToken: bearerToken } });

  if (!token) return null;

  return {
    accessToken: token.accessToken,
    accessTokenExpiresOn: token.accessTokenExpiresOn,
    client: { id: token.clientId },
    user: { id: token.userId },
  };
};

/**
 * Get client.
 */
module.exports.getClient = async function (clientId, clientSecret) {
  
  try {
    const client = await OauthClient.findOne({
      where: {
        clientId,
        clientSecret,
      },
    });

    if (!client) return null;
    return {
      clientId: client.client_id,
      clientSecret: client.client_secret,
      grants: ['authorization_code', 'password', 'refresh_token'],
      redirectUris: [client.redirect_uri],
    };
  } catch (error) {
    console.log("Error retrieving client:", error);
    return null;
  }
};

/**
 * Get refresh token.
 */
module.exports.getRefreshToken = async function (refreshToken) {
  const token = await OauthToken.findOne({ where: { refreshToken } });

  if (!token) return null;

  return {
    refreshToken: token.refreshToken,
    refreshTokenExpiresOn: token.refreshTokenExpiresOn,
    client: { id: token.clientId },
    user: { id: token.userId },
  };
};

/**
 * Get user (for password grant type).
 */
module.exports.getUser = async function (username, password) {
  const user = await User.findOne({
    where: {
      username,
      password, // Ensure passwords are hashed and verified securely in production
    },
  });

  if (!user) return null;

  return { id: user.id };
};

/**
 * Save access token.
 */
module.exports.saveToken = async function (token, client, user) {
  const savedToken = await OauthToken.create({
    accessToken: token.accessToken,
    accessTokenExpiresOn: token.accessTokenExpiresOn,
    refreshToken: token.refreshToken,
    refreshTokenExpiresOn: token.refreshTokenExpiresOn,
    clientId: client.id,
    userId: user.id,
  });

  return {
    accessToken: savedToken.accessToken,
    accessTokenExpiresOn: savedToken.accessTokenExpiresOn,
    refreshToken: savedToken.refreshToken,
    refreshTokenExpiresOn: savedToken.refreshTokenExpiresOn,
    client: { id: savedToken.clientId },
    user: { id: savedToken.userId },
  };
};

/**
 * Save authorization code.
 */
module.exports.saveAuthorizationCode = async function (code, client, user) {
  const savedCode = await OauthAuthorizationCode.create({
    authorizationCode: code.authorizationCode,
    expiresAt: code.expiresAt,
    redirectUri: code.redirectUri,
    scope: code.scope,
    clientId: client.id,
    userId: user.id,
  });

  return {
    authorizationCode: savedCode.authorizationCode,
    expiresAt: savedCode.expiresAt,
    redirectUri: savedCode.redirectUri,
    scope: savedCode.scope,
    client: { id: savedCode.clientId },
    user: { id: savedCode.userId },
  };
};

/**
 * Get authorization code.
 */
module.exports.getAuthorizationCode = async function (authorizationCode) {
  const code = await OauthAuthorizationCode.findOne({
    where: { authorizationCode },
  });

  if (!code) return null;

  return {
    authorizationCode: code.authorizationCode,
    expiresAt: code.expiresAt,
    redirectUri: code.redirectUri,
    scope: code.scope,
    client: { id: code.clientId },
    user: { id: code.userId },
  };
};

/**
 * Revoke authorization code.
 */
module.exports.revokeAuthorizationCode = async function (code) {
  const result = await OauthAuthorizationCode.destroy({
    where: { authorizationCode: code.authorizationCode },
  });

  return result > 0;
};
