const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { User, Client } = require('../models');

/**
 *  Author: Madeline Moldrem
 *
 *  Handles user registration with CSRF protection:
 *  - Generates a CSRF token when the registration page is accessed.
 *  - Validates the CSRF token upon form submission.
 *  - Checks for existing users by username and email.
 *  - Hashes the password and stores the new user in the database.
 *  - Creates a default client entry for the user.
 */


exports.getRegister = (req, res) => {
    
    const csrfToken = crypto.randomBytes(16).toString('hex')
    req.session.csrfToken = csrfToken;
    res.render('register', { csrf_token: csrfToken,})
};

exports.postRegister = async (req, res) => {
    const { username, password, email, date, first_name, last_name, csrf_token } = req.body;
    if (!username || !password || !email || !date || !first_name || !last_name) {
        return res.status(400).send('All fields are required');
    }

    if (csrf_token !== req.session.csrfToken) {
        return res.status(400).send('Invalid CSRF token');
    }

     const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
     
     if (!emailRegex.test(email)) {
         return res.status(400).send('Invalid email format');
     }
 
     // At least 8 characters, 1 letter, 1 number
     const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
     if (!passwordRegex.test(password)) {
         return res.status(400).send('Password must be at least 8 characters long and contain at least 1 letter and 1 number');
     }


    try {
        const existingUser = await User.findOne({ where: { username } }); // Check if the username already exists
        if (existingUser) {
            return res.status(400).send('Username already exists');
        }

        const existingUser2 = await User.findOne({ where: { email } }); // Check if the email already exists
        if (existingUser2) {
            return res.status(400).send('Email already exists');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({
            username,
            email,
            password_hash: hashedPassword,
            first_name,
            last_name,
            date_of_birth: date,
        }); // Insert the user into the database

        const newClient = await Client.create({
            client_secret: crypto.randomBytes(16).toString('hex'),
            client_name: `d${newUser.user_id}`, // d for default, the user id
            redirect_uri: '/callback',
            landing_page: 'dashboard', // TODO: In the future, allow this to be customized to the application's landing page.
            owner_id: newUser.user_id,
        });

        console.log(`User registered successfully: ${newUser.username}`);
        console.log(`Default registered successfully: ${newClient.client_name}`);
        res.redirect('/login');
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user');
    } 
};
