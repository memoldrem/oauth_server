const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { User, Client } = require('../models');

exports.getRegister = (req, res) => res.render('register');

exports.postRegister = async (req, res) => {
    const { username, password, email, date, first_name, last_name } = req.body;
    // * function to check passward strength * //
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
            redirect_uri: 'http://localhost:3001/callback',
            owner_id: newUser.user_id,
        });

        console.log(`User registered successfully: ${newUser.username}`);
        console.log(`Default registered successfully: ${newClient.client_name}`);
        res.redirect('/login');
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user');
    } // <- Fixed the missing bracket
};
