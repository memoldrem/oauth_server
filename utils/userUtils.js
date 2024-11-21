// /services/userService.js
const db = require('../models');  

// getUserByEmail - Finds user by email
async function getUserByEmail(email) {
    try {
        const user = await db.User.findOne({ where: { email } });
        return user;  // Return the user object or null if not found
    } catch (err) {
        console.error("Error finding user by email:", err);
        return null;  // Handle any errors and return null
    }
}

// getUserByID - Finds user by ID (for session deserialization)
async function getUserByID(id) {
    try {
        const user = await db.User.findByPk(id);  // Find user by primary key (ID)
        return user;  // Return the user object or null if not found
    } catch (err) {
        console.error("Error finding user by ID:", err);
        return null;  // Handle errors, return null if no user is found
    }
}

module.exports = {
    getUserByEmail,
    getUserByID
};
