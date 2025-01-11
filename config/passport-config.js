const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const db = require('../models'); // Adjust path as needed to access your database models

async function getUserByEmail(email) {
    try {
        const user = await db.User.findOne({ where: { email } });
        return user; 
    } catch (err) {
        console.error("Error finding user by email:", err);
        return null;
    }
}

async function getUserByID(id) {
    try {
        const user = await db.User.findByPk(id); // Find user by primary key (ID)
        return user; 
    } catch (err) {
        console.error("Error finding user by ID:", err);
        return null;
    }
}

function initializePassport(passport) {
    const authenticateUser = async (email, password, done) => {
        try {
            if (!email || !password) {
                console.error("Missing email or password");
                return done(null, false, { message: "Email and password are required" });
            }
            const user = await getUserByEmail(email);
            if (!user) {
                return done(null, false, { message: "Invalid email or password" });
            }

            const passwordMatch = await bcrypt.compare(password, user.password_hash);
            if (!passwordMatch) {
                console.log(`Incorrect password for email: ${email}`);
                return done(null, false, { message: "Invalid email or password" });
            }

            return done(null, user);
        } catch (err) {
            console.error(`Error during authentication for email ${email}:`, err);
            return done(err);
        }
    };

    passport.use(new LocalStrategy({ usernameField: 'email', passwordField: 'password', debug: true}, authenticateUser));



    passport.serializeUser((user, done) => {
         // probably need some error handling
        done(null, user.user_id);
    });
    
    passport.deserializeUser(async (id, done) => {
        const user = await getUserByID(id);
        if (!user) {
            console.log('User not found!');
            return done(new Error('User not found'));
        }
        done(null, user);
    });
}

module.exports = initializePassport;
