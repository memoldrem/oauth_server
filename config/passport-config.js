const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcryptjs')

function initializePassport(passport, getUserByEmail, getUserByID){
    const authenticateUser = async (email, password, done) => { // is it really async??
        const user = getUserByEmail(email) // use database???
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
    passport.use(new LocalStrategy({usernameField: 'email'}, authenticateUser)) // looks for email instead of default user
    passport.serializeUser((user, done) => done(null, user.id))
    passport.deserializeUser((id, done) => { 
        return done(null, getUserByID(id))
    })
}

module.exports = initializePassport;