// // routes/auth.js
// const express = require('express');
// const passport = require('passport');
// const router = express.Router();

// // Initialize the OAuth2 login route
// router.get('/login', passport.authenticate('oauth2'));

// // OAuth2 callback route
// router.get('/auth/example/callback', 
//   passport.authenticate('oauth2', { failureRedirect: '/login' }), // changed /login to /
//   (req, res) => {
//     // Successful authentication
//     res.redirect('/'); // Redirect to a specific route upon successful login
//   }
// );

// // Logout route
// router.get('/logout', (req, res, next) => {
//   req.logout(err => {
//     if (err) return next(err);
//     res.redirect('/'); // Redirect to home or login page after logout
//   });
// });

// module.exports = router;


