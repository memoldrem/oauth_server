const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcryptjs')
const { getUserByEmail, getUserByID } = require('../utils/userUtils'); 

function initializePassport(passport){
    const authenticateUser = async (email, password, done) => {
        const user = await getUserByEmail(email) // use database???
        if(user == null){
            return done(null, false, {message: "No user with that email"});
        }

        try {
            if(await bcrypt.compare(password, user.password)){
                return done(null, user)
            } else {
                return done(null, false, {message: "Password is incorrect"})
            }
        } catch(e) {
            done(e)
        }

    }
    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser));// looks for email instead of default user
    console.log("Registered Passport Strategies:", passport._strategies);
    passport.serializeUser((user, done) => done(null, user.id))
    passport.deserializeUser((id, done) => { 
        const userByID = getUserByID(id);
        return done(null, userByID)
    })
}

  

module.exports = initializePassport;