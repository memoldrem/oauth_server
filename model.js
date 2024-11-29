const { Sequelize, DataTypes } = require('sequelize');
require('dotenv').config();

// Initialize Sequelize with the database connection.
const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false
});

// Define the OAuth tokens model.
const OauthToken = sequelize.define('OauthToken', {
  accessToken: { type: DataTypes.STRING, field: 'access_token' },
  accessTokenExpiresOn: { type: DataTypes.DATE, field: 'access_token_expires_on' },
  refreshToken: { type: DataTypes.STRING, field: 'refresh_token' },
  refreshTokenExpiresOn: { type: DataTypes.DATE, field: 'refresh_token_expires_on' },
  clientId: { type: DataTypes.STRING, field: 'client_id' },
  userId: { type: DataTypes.INTEGER, field: 'user_id' },
}, {
  tableName: 'oauth_tokens',
  timestamps: false,
});

// Define the OAuth clients model.
const OauthClient = sequelize.define('OauthClient', {
  clientId: { type: DataTypes.STRING, primaryKey: true, field: 'client_id' },
  clientSecret: { type: DataTypes.STRING, field: 'client_secret' },
  redirectUri: { type: DataTypes.STRING, field: 'redirect_uri' },
}, {
  tableName: 'oauth_clients',
  timestamps: false,
});

// Define the users model.
const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  username: DataTypes.STRING,
  password: DataTypes.STRING, // Store hashed passwords for security.
}, {
  tableName: 'users',
  timestamps: false,
});

// Define the OAuth authorization codes model.
const OauthAuthorizationCode = sequelize.define('OauthAuthorizationCode', {
  authorizationCode: { type: DataTypes.STRING, primaryKey: true, field: 'authorization_code' },
  expiresAt: { type: DataTypes.DATE, field: 'expires_at' },
  redirectUri: { type: DataTypes.STRING, field: 'redirect_uri' },
  scope: { type: DataTypes.STRING },
  clientId: { type: DataTypes.STRING, field: 'client_id' },
  userId: { type: DataTypes.INTEGER, field: 'user_id' },
}, {
  tableName: 'oauth_authorization_codes',
  timestamps: false,
});


module.exports = {
  sequelize,
  OauthToken,
  OauthClient,
  User,
  OauthAuthorizationCode,
};

