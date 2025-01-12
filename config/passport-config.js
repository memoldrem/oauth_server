const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const db = require('../models'); 
const { Op } = require('sequelize');


async function getUserByEmailOrUser(input) { // ***get user by email or username
    try {
        const user = await db.User.findOne({
            where: {
              [Op.or]: [
                { email: input },   // Match email
                { username: input } // Match username
              ]
            }
          });
          
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
    const authenticateUser = async (username, password, done) => {
        try {
            if (!username || !password) {
                console.error("Missing email/user or password");
                return done(null, false, { message: "Email/user and password are required" });
            }
            const user = await getUserByEmailOrUser(username);
            if (!user) {
                return done(null, false, { message: "Invalid email/user or password" });
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
