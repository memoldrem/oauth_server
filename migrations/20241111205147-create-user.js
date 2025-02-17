'use strict';
/**
 * Author: Madeline Moldrem
 *
 * This migration creates the "Users" table with the following columns:
 * - user_id: Primary key, auto-increment integer.
 * - username: A non-null string for the user's name.
 * - email: A non-null string for the user's email.
 * - first_name: A non-null string for the user's first name.
 * - last_name: A non-null string for the user's last name.
 * - date_of_birth: A non-null date-only value for the user's birth date.
 * - password_hash: A non-null string storing the user's hashed password.
 * - role: A non-null string with a default value of "user".
 * - createdAt/updatedAt: Timestamps automatically managed by Sequelize.
 */
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('users', {
      user_id: {
        type: Sequelize.INTEGER,
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        // If you prefer the physical column to be named "userID", uncomment the next line:
        // field: 'userID'
      },
      username: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      email: {
        type: Sequelize.STRING,
        allowNull: false,
        // Set unique: true if you want email addresses to be unique:
        unique: false,
      },
      first_name: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      last_name: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      date_of_birth: {
        type: Sequelize.DATEONLY,
        allowNull: false,
      },
      password_hash: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      role: {
        type: Sequelize.STRING,
        allowNull: false,
        defaultValue: 'user',
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
      }
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('users');
  }
};
