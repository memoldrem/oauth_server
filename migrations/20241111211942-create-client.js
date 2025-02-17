'use strict';
/**
 * Author: Madeline Moldrem
 *
 * This migration creates the Clients table with the following columns:
 * - client_id: Primary key, auto-increment integer.
 * - client_secret: A string (not null) that stores the client's secret.
 * - client_name: A string (not null) that stores the client's name.
 * - redirect_uri: A string (not null) for the client's redirect URI.
 * - landing_page: An optional string for the client's landing page.
 * - owner_id: An integer (not null) that references the user who owns this client.
 * - createdAt/updatedAt: Timestamps automatically managed by Sequelize.
 */
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('clients', {
      client_id: {
        type: Sequelize.INTEGER,
        allowNull: false,
        autoIncrement: true,
        primaryKey: true
      },
      client_secret: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      client_name: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      redirect_uri: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      landing_page: {
        type: Sequelize.STRING,
        allowNull: true,
      },
      owner_id: {
        type: Sequelize.INTEGER,
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
      }
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('clients');
  }
};
