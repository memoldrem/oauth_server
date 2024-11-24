const express = require('express');
const session = require('express-session');
const passport = require('passport');
const bodyParser = require('body-parser');
const oauth2orize = require('oauth2orize');
const { Client, User, AuthorizationCode, Token } = require('./models'); // Define your Sequelize models

// Create OAuth2 server
const oauthServer = oauth2orize.createServer();

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(
  session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Passport serialization
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findByPk(id);
  done(null, user);
});

// Passport Local Strategy (for login)
passport.use(
  new (require('passport-local').Strategy)(
    async (username, password, done) => {
      try {
        const user = await User.findOne({ where: { username } });
        if (!user || !(await user.verifyPassword(password))) {
          return done(null, false);
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Register grant type for authorization code
oauthServer.grant(
  oauth2orize.grant.code(async (client, redirectUri, user, ares, done) => {
    try {
      const code = Math.random().toString(36).substring(7); // Replace with secure code generation
      await AuthorizationCode.create({
        code,
        clientID: client.clientID,
        redirectUri,
        userId: user.id,
      });
      done(null, code);
    } catch (err) {
      done(err);
    }
  })
);

// Exchange authorization code for access token
oauthServer.exchange(
  oauth2orize.exchange.code(async (client, code, redirectUri, done) => {
    try {
      const authCode = await AuthorizationCode.findOne({ where: { code } });
      if (!authCode || authCode.redirectUri !== redirectUri || authCode.clientID !== client.clientID) {
        return done(null, false);
      }

      const token = Math.random().toString(36).substring(7); // Replace with secure token generation
      await Token.create({
        token,
        userId: authCode.userId,
        clientID: client.clientID,
      });

      done(null, token);
    } catch (err) {
      done(err);
    }
  })
);
