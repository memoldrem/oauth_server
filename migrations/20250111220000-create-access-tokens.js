'use strict';
/**
 * Author: Madeline Moldrem
 *
 * This migration creates the "access_tokens" table with the following columns:
 * - access_token: Primary key, a string that stores the access token.
 * - user_id: An integer (not null) referencing the user.
 * - client_id: An integer (not null) referencing the client.
 * - expires_at: A date (not null) representing when the token expires.
 * - createdAt/updatedAt: Timestamps automatically managed by Sequelize.
 */
module.exports = {
    up: async (queryInterface, Sequelize) => {
        await queryInterface.createTable('access_tokens', {
            access_token: {
                type: Sequelize.STRING,
                allowNull: false,
                primaryKey: true,
            },
            user_id: {
                type: Sequelize.INTEGER,
                allowNull: false,
            },
            client_id: {
                type: Sequelize.INTEGER,
                allowNull: false,
            },
            expires_at: {
                type: Sequelize.DATE,
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
        await queryInterface.dropTable('access_tokens');
    }
};
