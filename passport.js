const OAuth2Strategy = require('passport-oauth2');
const User = require('./models/User'); // Make sure you have a User model

passport.use(new OAuth2Strategy({
    authorizationURL: 'https://www.example.com/oauth2/authorize',
    tokenURL: 'https://www.example.com/oauth2/token',
    clientID: process.env.EXAMPLE_CLIENT_ID,
    clientSecret: process.env.EXAMPLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/example/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    // This function is called after the user is authenticated by the OAuth2 provider
    User.findOrCreate({ exampleId: profile.id }, function (err, user) {
      return cb(err, user);  // Find or create the user in your database based on the profile information
    });
  }
));

