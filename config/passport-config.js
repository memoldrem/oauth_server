const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const { getUserByEmail, getUserByID } = require('../utils/userUtils'); // Assuming utils folder is correctly structured

function initializePassport(passport) {
    const authenticateUser = async (email, password, done) => {
        try {
            const user = await getUserByEmail(email); // Querying the database

            if (!user) {
                return done(null, false, { message: "No user with that email" });
            }

            console.log('Password:', password);
            console.log("Password from DB:", user.passwordHash);

            // Comparing the hashed password with the input password
            if (await bcrypt.compare(password, user.passwordHash)) {
                return done(null, user);
            } else {
                return done(null, false, { message: "Password is incorrect" });
            }
        } catch (err) {
            console.error('Error during authentication:', err);
            return done(err);
        }
    };

    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser)); // Customizing username field to 'email'

    passport.serializeUser((user, done) => {
        // Ensure user and user.id exist before proceeding
        if (!user) {
            return done(new Error("User is missing"));
        } else if (!user.userID) {
            return done(new Error("User ID is missing"));
        }
        return done(null, user.userID); // Only store user ID in session
    });

    passport.deserializeUser(async (userID, done) => {
        try {
            const user = await getUserByID(userID); // Await the asynchronous getUserByID call
            if (!user) {
                return done(new Error("User not found"));
            }
            return done(null, user); // Return the full user object after retrieving it
        } catch (err) {
            console.error('Error deserializing user:', err);
            return done(err); // Handle any errors during deserialization
        }
    });
}

module.exports = initializePassport;
