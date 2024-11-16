const express = require('express');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const dotenv = require('dotenv');

// const { OAuth2Server } = require('oauth2-server'); // OAuth2 server library
const bodyParser = require('body-parser');
const db = require('./models');
const User = db.User;


// // const authenticate = require('./middleware/authenticate'); // Custom middleware for protected routes

dotenv.config();

const app = express();
const port = 3000;

// const initializePassport = require('./config/passport-config')
// initializePassport(passport, //*user email, user id*
//   // find user thru email in database!!!! need arg
//   // also pass in user id
//   )

app.set('view engine', 'ejs');
app.use(bodyParser.json());
app.use(express.urlencoded({extended: true})); // used to be false
app.use(flash());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(express.static('public'));





// login and authenticate locally using passport
app.get('/', (req, res) => {
  res.render('login.ejs')
})

// app.post('/', passport.authenticate({ 
//   successRedirect: '/dashboard',  // redirect if login is successful
//   failureRedirect: '/',         // redirect if login fails
//   failureFlash: true,
// }))



// Register pages
app.get('/register', (req, res) => {
   res.render('register.ejs')

})

app.post('/register', async (req, res) => {
  try {

    const { username, email, password } = req.body;

    const existingUser = await User.findOne({
      where: { username: req.body.username }
    });

    if (existingUser) {
      req.flash('error', 'User with this email already exists.'); // we could make this cleaner. lol
      return res.redirect('/register'); 
    } 

    const hashedPassword = await bcrypt.hash(password, 10)

    const newUser = await User.create({
      username,
      email,
      passwordHash: hashedPassword,
    });


    res.redirect('/')
  } catch(error) {
    console.error(error);
    res.redirect('/register')
  }
})

// // // Success pages
// // app.get('/dashboard', checkAuthenticated, (req, res) => {
// //   res.render('dashboard.ejs')
// // })


// // function checkAuthenticated(req, res, next){ // middleware to check authentication!
// //   if(req.isAuthenticated()){
// //     return next();
// //   }
// //   res.redirect('/');
// // }

// app.listen(port, () => {
//   console.log(`Server running at http://localhost:3000}`);
// });






// // const oauth = new OAuth2Server({
// //   model: require('./config/oauth-model'), // Custom OAuth model for authorization
// //   accessTokenLifetime: 3600, // one hour lifetime
// //   allowBearerTokensInQueryString: true, // tokens can be passed in as query strings
// // });




// // Authorization Endpoint
// // this where user "consents"
// // Authorization Server will automatically redirect the user back to the redirect URI 
// // you specified when you first set up the OAuth flow (this is where you receive the authorization code)
// // app.get('/auth', (req, res) => {
// //   const { client_id, redirect_uri, response_type, scope, state } = req.query;

// //   // Step 1: Validate client_id and response_type
// //   if (client_id !== process.env.CLIENT_ID || response_type !== 'code') {
// //     return res.status(400).json({ error: 'Invalid request' });
// //   }

// //   // Step 2: Check if user is authenticated
// //   if (!req.isAuthenticated()) {
// //     return res.redirect(`/login?redirect_uri=${req.originalUrl}`); // Redirect unauthenticated users to login page
// //   }

// //   // Step 3: Render consent page if user is authenticated
// //   res.render('consent', {
// //     client_id,
// //     redirect_uri,
// //     scope,
// //     state
// //   });
// // });

// // // Consent Page Form Handling (when user clicks "Allow" or "Deny" on consent.ejs)
// // app.post('/auth/consent', (req, res) => {
// //   const { client_id, redirect_uri, scope, state, consent } = req.body;

// //   if (consent === 'allow') {
// //     // Generate authorization code
// //     const authorizationCode = generateAuthCode(req.user);

// //     // Redirect back to client with authorization code
// //     res.redirect(`${redirect_uri}?code=${authorizationCode}&state=${state}`);
// //   } else {
// //     // Redirect back to client with error if consent is denied
// //     res.redirect(`${redirect_uri}?error=access_denied&state=${state}`);
// //   }
// // });


// // // token endpount!!
// // app.post('/oauth/token', (req, res, next) => { // authorization code is posted in exachange for access token
// //   const request = new OAuth2Server.Request(req);
// //   const response = new OAuth2Server.Response(res); 

// //   oauth
// //     .token(request, response)
// //     .then(token => {
// //       res.json(token); // send access token to client
// //     })
// //     .catch(err => {
// //       res.status(err.code || 500).json(err);
// //     });
// // });










db.sequelize.sync({ force: false }) // Change to true if you want to reset tables (not recommended in production)
  .then(() => {
    // console.log("Models synced with the database!");

    // Log db.User to check if the User model is defined
    // console.log(db.User);  // Check if db.User is defined

    // Start the server after sync
    app.listen(3000, () => {
      console.log("Server is running on http://localhost:3000");
    });
  })
  .catch((err) => {
    console.error("Error syncing models:", err);
  });
