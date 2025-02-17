'use strict';
/**
 * Author: Madeline Moldrem
 *
 * This migration creates the "Tokens" table with the following columns:
 * - token_id: Primary key, auto-increment integer.
 * - access_token: A non-null, unique string storing the access token.
 * - refresh_token: A unique string storing the refresh token.
 * - expires_at: A non-null date indicating when the token expires.
 * - user_id: A non-null integer referencing the user.
 * - client_id: A non-null string referencing the client.
 * - createdAt/updatedAt: Timestamps automatically managed by Sequelize.
 */
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('tokens', {
      token_id: {
        type: Sequelize.INTEGER,
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
      },
      access_token: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true,
      },
      refresh_token: {
        type: Sequelize.STRING,
        unique: true,
      },
      expires_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      user_id: {
        type: Sequelize.INTEGER,
        allowNull: false,
      },
      client_id: {
        type: Sequelize.STRING,  // Note: If your Clients table uses an integer for client_id, consider using INTEGER here.
        allowNull: false,
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
      },
    });
  },
  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('tokens');
  }
};
